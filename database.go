package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"

	"github.com/EternityX/tiel-secrets/db"
)

func initDatabase() (*db.PrismaClient, error) {
	client := db.NewClient()
	if err := client.Prisma.Connect(); err != nil {
		return nil, err
	}

	return client, nil
}

func shutdownDatabase(client *db.PrismaClient) {
	if err := client.Prisma.Disconnect(); err != nil {
		panic(err)
	}
}

func updateSiteStatus(client *db.PrismaClient, url string, status db.ScrapeStatus) (updated *db.SiteModel, err error) {
	ctx := context.Background()

	updated, err = client.Site.FindUnique(
		db.Site.URL.Equals(url),
	).Update(
		db.Site.Status.Set(status),
	).Exec(ctx)

	return updated, err
}

func updateSiteErrors(client *db.PrismaClient, url string, errors []error) (updated *db.SiteModel, err error) {
	ctx := context.Background()

	// Convert []error to []string
	errorStrs := make([]string, len(errors))
	for i, e := range errors {
		errorStrs[i] = e.Error()
	}

	// First find the site
	site, err := client.Site.FindUnique(
		db.Site.URL.Equals(url),
	).Exec(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to find site: %w", err)
	}

	// Create transaction params for each error
	var txs []db.PrismaTransaction

	for _, errStr := range errorStrs {
		tx := client.Error.CreateOne(
			db.Error.Site.Link(
				db.Site.ID.Equals(site.ID),
			),
			db.Error.Error.Set(errStr),
		).Tx()
		txs = append(txs, tx)
	}

	// Execute all error creations in a single transaction
	if err := client.Prisma.Transaction(txs...).Exec(ctx); err != nil {
		return nil, fmt.Errorf("failed to create error records: %w", err)
	}

	updated = site
	return updated, nil
}

// func createSite(client *db.PrismaClient, url string) (created *db.SiteModel, err error) {
// 	ctx := context.Background()

// 	created, err = client.Site.CreateOne(
// 		db.Site.URL.Set(url),
// 	).Exec(ctx)

// 	return created, err
// }

func processSites(config *Config, ctx context.Context, client *db.PrismaClient) error {
	ignoreCompleted := os.Getenv("IGNORE_COMPLETED") == "true"
	if ignoreCompleted {
		log.Println("Ignoring completed sites")
	}

	// Find all existing sites for these URLs
	found, err := client.Site.FindMany(
		db.Site.URL.In(config.BaseURLs),
	).Exec(ctx)

	if err != nil {
		return fmt.Errorf("error finding site entries: %v", err)
	}

	// Create maps for existing URLs and completed URLs
	existingURLs := make(map[string]bool)
	completedURLs := make(map[string]bool)

	for _, site := range found {
		existingURLs[site.URL] = true
		if site.Status == db.ScrapeStatusCompleted {
			completedURLs[site.URL] = true
		}
	}

	// Create only sites that don't exist
	var sitesToCreate []string
	for _, url := range config.BaseURLs {
		if !existingURLs[url] {
			sitesToCreate = append(sitesToCreate, url)
		}
	}

	// Create new sites
	if len(sitesToCreate) > 0 {
		for _, url := range sitesToCreate {
			_, err := client.Site.CreateOne(
				db.Site.URL.Set(url),
				db.Site.Status.Set(db.ScrapeStatusPending),
			).Exec(ctx)
			
			if err != nil {
				return fmt.Errorf("error creating site entry for %s: %v", url, err)
			}
		}
		log.Printf("Created %d new site entries", len(sitesToCreate))
	}

	// Remove completed URLs from BaseURLs
	if !ignoreCompleted {
		config.mu.Lock()
		config.BaseURLs = slices.DeleteFunc(config.BaseURLs, func(u string) bool {
				return completedURLs[u]
			})
		config.mu.Unlock()
	}

	log.Printf("Found %d existing sites (%d completed), %d sites to process", 
		len(found), len(completedURLs), len(config.BaseURLs))
		
	return nil
}