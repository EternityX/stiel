package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/EternityX/tiel-secrets/db"
	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
	"github.com/joho/godotenv"
)

type Config struct {
	BaseURLs            []string
	Subdomains         []string
	Directories        []string
	Keywords           []KeywordPattern
	FileTypes          []string
	IgnoreStatusCodes  []int
	Parallelism        int
	RandomDelay        time.Duration
	mu                 *sync.Mutex
	Timeout            time.Duration
	RetryCount         int
	RetryDelay         time.Duration
}

type Result struct {
	URL      string
	Keyword  string
	Count    int
	FileType string
}

type Search struct {
	URL      string
	Keywords []KeywordResult
}

type domainStatus struct {
	visited bool
	errors  []error
	mu      sync.Mutex
}

func extractDomain(url string) string {
	parts := strings.Split(strings.Split(url, "://")[1], "/")
	return parts[0]
}

func visitURLs(c *colly.Collector, config Config, ctx context.Context, client *db.PrismaClient) error {
	var wg sync.WaitGroup
	errorChan := make(chan error, (len(config.Subdomains)+1) * len(config.Directories) * len(config.BaseURLs))

	// Handle concurrent directory visits for a given base URL
	visitDirectories := func(baseURL string) error {
		var dirWg sync.WaitGroup
		dirErrors := make(chan error, len(config.Directories))
		
		for _, dir := range config.Directories {
			dirWg.Add(1)
			
			go func(dir string) {
				defer dirWg.Done()
				
				fullURL := baseURL + dir
				if err := c.Visit(fullURL); err != nil {
					dirErrors <- fmt.Errorf("error visiting %s: %v", fullURL, err)
				}
			}(dir)
		}
		
		go func() {
			dirWg.Wait()
			close(dirErrors)
		}()

		for err := range dirErrors {
			errorChan <- err
		}
		
		return nil
	}

	// Handle DNS resolution and directory visits for a URL
	visitSingleURL := func(url string) {
		defer wg.Done()
		
		host := extractDomain(url)
		if _, err := net.LookupHost(host); err != nil {
			if strings.Contains(err.Error(), "no such host") {
				//color.Yellow("Skipping %s: DNS resolution failed\n", url)
				//errorChan <- fmt.Errorf("DNS resolution failed for %s: %v", url, err)
				return
			}
			
			errorChan <- err
			return
		}

		// log.Printf("Attempting to visit directories for %s\n", url)
		if err := visitDirectories(url); err != nil {
			errorChan <- fmt.Errorf("error visiting directories for %s: %v", url, err)
		}
	}

	// Visit each base URL and its subdomains
	for _, baseURL := range config.BaseURLs {
		// Visit base domain
		wg.Add(1)

		baseURL := baseURL
		go visitSingleURL(baseURL)

		_, err := updateSiteStatus(client, baseURL, db.ScrapeStatusProcessing)
		if err != nil {
			log.Printf("Error updating site status: %v", err)
			continue
		}

		// Visit subdomains for this base URL
		baseDomain := extractDomain(baseURL)
		scheme := strings.Split(baseURL, "://")[0]

		for _, subdomain := range config.Subdomains {
			wg.Add(1)

			subdomain := subdomain
			
			go func() {
				subdomainURL := fmt.Sprintf("%s://%s.%s", scheme, subdomain, baseDomain)
				visitSingleURL(subdomainURL)
			}()
		}
	}

	wg.Wait()
	close(errorChan)

	// Collect any errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple errors occurred: %v", errors)
	}

	return nil
}

func newScraper(config Config) *colly.Collector {
	// Collect all domains that should be allowed
	allowedDomains := make([]string, 0)
	
	for _, baseURL := range config.BaseURLs {
		baseDomain := extractDomain(baseURL)
		allowedDomains = append(allowedDomains, baseDomain)
		
		// Add subdomains for this base domain
		for _, subdomain := range config.Subdomains {
			allowedDomains = append(allowedDomains, subdomain+"."+baseDomain)
		}
	}

	log.Printf("Allowed domains: %v\n\n", allowedDomains)

	collector := colly.NewCollector(
		colly.AllowedDomains(allowedDomains...),
		colly.Async(true),
		colly.MaxDepth(2),
	)

	collector.SetRequestTimeout(config.Timeout)

	return collector
}

func scrape(config *Config, ctx context.Context, client *db.PrismaClient) ([]Search, error) {
	log.Printf("Starting scan of %d URLs...", len(config.BaseURLs))
	searches := make([]Search, 0)
	scripts := make([]string, 0)
	
	var searchMutex sync.Mutex
	var scriptsMutex sync.Mutex
	
	// Counter for processed URLs
	processedCount := 0
	
	// Function to save secrets to database
	saveSecretsBatch := func(searchBatch []Search) error {
		log.Printf("Saving batch of secrets from %d URLs to database...", len(searchBatch))
		
		for _, search := range searchBatch {
			for _, keyword := range search.Keywords {
				_, err := client.Secret.CreateOne(
					db.Secret.Secret.Set(keyword.EnvVariable),
					db.Secret.Risk.Set(keyword.Risk),
					db.Secret.SiteURL.Set(search.URL),
				).Exec(ctx)
				
				if err != nil {
					log.Printf("Error saving secret from %s: %v", search.URL, err)
					continue
				}
			}
		}
		
		return nil
	}
	
	// Track status for each domain and its subdomains
	domainStatuses := make(map[string]*domainStatus)
	for _, baseURL := range config.BaseURLs {
		baseDomain := extractDomain(baseURL)
		domainStatuses[baseDomain] = &domainStatus{}
		
		// Add subdomains
		for _, sub := range config.Subdomains {
			subdomain := fmt.Sprintf("%s.%s", sub, baseDomain)
			domainStatuses[subdomain] = &domainStatus{}
		}
	}
	
	c := newScraper(*config)
	c.Limit(&colly.LimitRule{
		Parallelism: config.Parallelism,
		RandomDelay: config.RandomDelay,
	})
	
	c.OnHTML("script", func(e *colly.HTMLElement) {
		src := e.Attr("src")
		if src == "" || !strings.HasSuffix(src, ".js") || strings.HasPrefix(src, "http") {
			return
		}
		
		scriptsMutex.Lock()
		// Check if the script has already been processed
		if slices.Contains(scripts, src) {
			scriptsMutex.Unlock()
			return
		}

		// Add the script to the list of processed scripts
		scripts = append(scripts, src)
		scriptsMutex.Unlock()

		log.Printf("Script found: %s\n", src)

		go func() {
			err := c.Visit(e.Request.AbsoluteURL(src))
			if err != nil {
				log.Printf("Error visiting script %s: %v\n", src, err)
			}
		}()
	})

	c.OnResponse(func(r *colly.Response) {
		domain := extractDomain(r.Request.URL.String())
		log.Printf("Successfully scanned: %s", r.Request.URL)

		if status, exists := domainStatuses[domain]; exists {
			status.mu.Lock()
			status.visited = true
			status.mu.Unlock()
		}

		content := string(r.Body)
		matches := findKeywordMatches(content, config.Keywords)
		
		if len(matches) > 0 {
			searchMutex.Lock()
			searches = append(searches, Search{
				URL:      r.Request.URL.String(),
				Keywords: matches,
			})
			
			// Increment processed count
			processedCount++
			
			// If we've hit 100 URLs with results, save to database
			if processedCount%100 == 0 {
				// Create a copy of the searches slice for the batch
				searchBatch := make([]Search, len(searches))
				copy(searchBatch, searches)
				
				// Clear the searches slice
				searches = searches[:0]
				
				searchMutex.Unlock()
				
				// Save batch in a separate goroutine
				go func() {
					if err := saveSecretsBatch(searchBatch); err != nil {
						log.Printf("Error saving secrets batch: %v", err)
					}
				}()
			} else {
				searchMutex.Unlock()
			}
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		if config.IgnoreStatusCodes != nil {
			for _, code := range config.IgnoreStatusCodes {
				if r.StatusCode == code {
					// log.Printf("Ignoring status code %d for %s\n", code, r.Request.URL)
					return
				}
			}
		}

		domain := extractDomain(r.Request.URL.String())
		if status, exists := domainStatuses[domain]; exists {
			status.mu.Lock()

			status.errors = append(status.errors, fmt.Errorf("error scraping %s (Status: %d): %v", 
				r.Request.URL, r.StatusCode, err))

			status.mu.Unlock()
		}

		log.Printf("Error scraping %s (Status: %d): %v\n", r.Request.URL, r.StatusCode, err)
	})

	if err := visitURLs(c, *config, ctx, client); err != nil {
		return nil, fmt.Errorf("error visiting domains: %v", err)
	}

	c.Wait()

	// Save any remaining searches
	if len(searches) > 0 {
		if err := saveSecretsBatch(searches); err != nil {
			log.Printf("Error saving final secrets batch: %v", err)
		}
	}

	// Update status for each base URL
	for _, baseURL := range config.BaseURLs {
		baseDomain := extractDomain(baseURL)
		status := domainStatuses[baseDomain]
		
		status.mu.Lock()

		wasVisited := status.visited
		hasErrors := len(status.errors) > 0
		
		status.mu.Unlock()

		var finalStatus db.ScrapeStatus
		if hasErrors {
			finalStatus = db.ScrapeStatusPartial
		} else if wasVisited {
			finalStatus = db.ScrapeStatusCompleted
		} else {
			finalStatus = db.ScrapeStatusFailed
		}

		_, err := updateSiteStatus(client, baseURL, finalStatus)
		if err != nil {
			log.Printf("Error updating site status to %s for %s: %v", finalStatus, baseURL, err)
		}
	}

	// After c.Wait(), check if all domains failed
	allFailed := true
	var finalErrors []error

	for _, status := range domainStatuses {
		status.mu.Lock()
		if status.visited {
			allFailed = false
		} else if len(status.errors) > 0 {
			finalErrors = append(finalErrors, status.errors...)
		}

		status.mu.Unlock()
	}

	if allFailed && len(finalErrors) > 0 {
		return searches, fmt.Errorf("scraping failed for all domains: %v", finalErrors)
	}
	
	return searches, nil
}

func getScrapeURLs(client *db.PrismaClient, ctx context.Context) ([]string, error) {
	log.Println("Fetching URLs from Scrape table...")
	scrapes, err := client.Scrape.FindMany().
		Skip(0).
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scrapes: %v", err)
	}
	log.Printf("Found %d entries in Scrape table after offset", len(scrapes))

	// Use a map to deduplicate URLs
	urlMap := make(map[string]struct{})
	for _, scrape := range scrapes {
		if scrape.Link != "" {
			urlMap[scrape.Link] = struct{}{}
		}
	}

	// Convert map keys to slice
	urls := make([]string, 0, len(urlMap))
	for url := range urlMap {
		urls = append(urls, url)
	}

	log.Printf("Extracted %d unique URLs to scan", len(urls))
	if len(urls) > 0 {
		log.Println("Sample URLs:")
		// Print first 5 URLs as sample
		for i, url := range urls {
			if i >= 5 {
				break
			}
			log.Printf("  - %s", url)
		}
		if len(urls) > 5 {
			log.Printf("  ... and %d more", len(urls)-5)
		}
	}

	return urls, nil
}

func scrapeInBatches(config *Config, ctx context.Context, client *db.PrismaClient, printers map[string]*color.Color) error {
	const batchSize = 25
	
	totalURLs := len(config.BaseURLs)
	log.Printf("Processing %d URLs in batches of %d", totalURLs, batchSize)
	
	for i := 0; i < totalURLs; i += batchSize {
		end := i + batchSize
		if end > totalURLs {
			end = totalURLs
		}
		
		batchURLs := config.BaseURLs[i:end]
		log.Printf("Processing batch %d/%d (%d URLs)", (i/batchSize)+1, 
			(totalURLs+batchSize-1)/batchSize, len(batchURLs))
		
		// Create config for this batch
		batchConfig := *config
		batchConfig.BaseURLs = batchURLs
		
		searches, err := scrape(&batchConfig, ctx, client)
		if err != nil {
			log.Printf("Error in batch %d: %v", (i/batchSize)+1, err)
			continue // Continue with next batch even if this one fails
		}
		
		// Print summary for this batch
		printSummary(searches, printers)
	}
	
	return nil
}

func main() {
	initLogger()
	
	ctx := context.Background()

	client, err := initDatabase()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Printf("Connected!")

	err = godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Get URLs from Scrape table
	urls, err := getScrapeURLs(client, ctx)
	if err != nil {
		log.Fatalf("Failed to get scrape URLs: %v", err)
	}

	config := Config{
		BaseURLs: urls,
		Subdomains: []string{
			"app", "dashboard", "admin",
		},
		Directories: []string{
			"/",
			"/authentication",
			"/dashboard",
			"/login",
			"/sign-in",
			"/sign-up",
			"/signin",
			"/signup",
			"/register",
			"/auth",
			"/auth/login",
			"/auth/sign-in",
			"/auth/sign-up",
			"/auth/signin",
			"/auth/signup",
			"/auth/register",
		},
		Keywords: []KeywordPattern{
			{
				Keyword: "https://[a-zA-Z0-9-]+\\.supabase\\.co",
				Label:   "Supabase URL",
				Match:   REGEX,
				Risk:    "medium",
			},
			{
				Keyword: "([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN)[A-Za-z0-9_]*)[\"'\\s]*:[\"'\\s]*[\"']([^\"']+)[\"']",
				Label:   "API Key",
				Match:   REGEX,
				Risk:    "unknown",
			},
		},
		IgnoreStatusCodes: []int{404, 403},
		Parallelism:      50,
		RandomDelay:      500 * time.Millisecond,
		RetryCount:       2,
		RetryDelay:       1 * time.Second,
		mu:              &sync.Mutex{},
		Timeout:         15 * time.Second,
	}

	printers := map[string]*color.Color{
		"title":    color.New(color.FgCyan, color.Bold),
		"success":  color.New(color.FgGreen),
		"warning":  color.New(color.FgYellow),
		"error":    color.New(color.FgRed),
		"critical": color.New(color.FgMagenta, color.Bold),
	}

	if err := processSites(&config, ctx, client); err != nil {
		log.Fatalf("Error processing sites: %v", err)
	}

	if len(config.BaseURLs) == 0 {
		color.Blue("No sites to scrape")
		return
	}

	// Replace single scrape call with batch processing
	if err := scrapeInBatches(&config, ctx, client, printers); err != nil {
		log.Fatalf("Error during batch scraping: %v\n", err)
	}

	shutdownDatabase(client)
}