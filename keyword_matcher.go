package main

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
)

type MatchType string

type KeyPattern struct {
	Type     string
	Patterns []string
	Risk     string
}

type KeywordPattern struct {
	Keyword string
	Label   string
	Match   MatchType
	Risk    string
}

type KeywordResult struct {
	Keyword      string
	Label        string
	Count        int
	Risk         string
	MatchedValue string
	EnvVariable  string
}

type Match struct {
	Pattern     KeywordPattern
	Value       string
	EnvVar      string
	Confidence  float64
	Label       string
}

const (
	TEXT  MatchType = "text"
	REGEX MatchType = "regex"
)

const (
	CONFIDENCE_THRESHOLD = 0.7
)

var keyPatterns = []KeyPattern{
	{
		Type:     "Stripe",
		Patterns: []string{"stripe", "sk_live", "sk_test"},
		Risk:     "critical",
	},
	{
		Type:     "Stripe",
		Patterns: []string{"stripe", "pk_live", "pk_test"},
		Risk:     "none",
	},
	{
		Type:     "OpenAI",
		Patterns: []string{"openai", "sk-"},
		Risk:     "high",
	},
	{
		Type:     "ElevenLabs",
		Patterns: []string{"eleven",},
		Risk:     "high",
	},
	{
		Type:     "Supabase",
		Patterns: []string{"supabase", "service_role"},
		Risk:     "critical",
	},
	{
		Type:     "Supabase",
		Patterns: []string{"supabase"},
		Risk:     "medium",
	},
}

func calculateConfidence(envVar string) (float64, string, string) {
	score := 0.0
	matchedType := ""
	risk := "unknown"
	
	lowerEnvVar := strings.ToLower(envVar)
	
	// Check for specific key patterns
	for _, keyPattern := range keyPatterns {
		patternMatches := 0
		for _, p := range keyPattern.Patterns {
			if strings.Contains(lowerEnvVar, p) {
				patternMatches++
			}
		}
		
		if patternMatches > 0 {
			typeScore := float64(patternMatches) / float64(len(keyPattern.Patterns)) * 0.8
			if typeScore > score {
				score = typeScore
				matchedType = keyPattern.Type
				risk = keyPattern.Risk
			}
		}
	}
	
	// Additional points for common patterns
	if strings.Contains(lowerEnvVar, "key") {
		score += 0.1
	}
	if strings.Contains(lowerEnvVar, "secret") {
		score += 0.1
	}
	if strings.Contains(lowerEnvVar, "token") {
		score += 0.1
	}
	
	return score, matchedType, risk
}

func findKeywordMatches(content string, patterns []KeywordPattern) []KeywordResult {
	results := make([]KeywordResult, 0)
	seenValues := make(map[string]bool)
	var matchesMutex sync.Mutex
	var wg sync.WaitGroup
	
	matches := make([]Match, 0)
	
	for _, pattern := range patterns {
		wg.Add(1)
		go func(pattern KeywordPattern) {
			defer wg.Done()
			
			var found [][]string
			
			if pattern.Match == TEXT {
				if strings.Contains(content, pattern.Keyword) {
					found = [][]string{{pattern.Keyword}}
				}
			} else {
				regex, err := regexp.Compile(pattern.Keyword)
				if err != nil {
					return
				}
				found = regex.FindAllStringSubmatch(content, -1)
			}
			
			localMatches := make([]Match, 0)
			for _, match := range found {
				if len(match) == 0 {
					continue
				}

				var value, envVar string
				
				if pattern.Match == TEXT {
					value = match[0]
					envVar = match[0]
				} else {
					if len(match) == 1 {
						value = match[0]
						envVar = match[0]
					} else if len(match) > 3 {
						value = match[3]
						envVar = match[2]
					} else {
						value = match[len(match)-1]
						envVar = match[0]
					}
				}
				
				// Skip if we've seen this value
				if seenValues[value] {
					continue
				}
				
				confidence, matchedType, risk := calculateConfidence(envVar)
				
				label := "API Key"
				if matchedType != "" {
					label = matchedType + " API Key"
				}
				
				localMatches = append(localMatches, Match{
					Pattern:    pattern,
					Value:     value,
					EnvVar:    envVar,
					Confidence: confidence,
					Label:     label,
				})
				
				localMatches[len(localMatches)-1].Pattern.Risk = risk
			}
			
			if len(localMatches) > 0 {
				matchesMutex.Lock()
				matches = append(matches, localMatches...)
				matchesMutex.Unlock()
			}
		}(pattern)
	}
	
	wg.Wait()
	
	// Sort matches by confidence
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})
	
	// Take highest confidence match for each value, excluding "none" risk
	for _, match := range matches {
		if seenValues[match.Value] {
			continue
		}
		
		// Skip results with "none" risk level
		if match.Pattern.Risk == "none" {
			continue
		}

		printKeywordResult(KeywordResult{
			Keyword:      match.Pattern.Keyword,
			Label:        match.Label,
			Count:        1,
			Risk:         match.Pattern.Risk,
			MatchedValue: match.Value,
			EnvVariable:  match.EnvVar,
		}, color.New(color.FgGreen))
		
		seenValues[match.Value] = true
		results = append(results, KeywordResult{
			Keyword:      match.Pattern.Keyword,
			Label:        match.Label,
			Count:        1,
			Risk:         match.Pattern.Risk,
			MatchedValue: match.Value,
			EnvVariable:  match.EnvVar,
		})
	}
	
	return results
} 