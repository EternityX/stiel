package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/fatih/color"
)

func printSearchResult(search Search, titlePrinter, successPrinter *color.Color) {
	titlePrinter.Printf("\nFile: %s\n", search.URL)

	for _, result := range search.Keywords {
		printKeywordResult(result, successPrinter)
	}
}

func getRiskPrinter(risk string) *color.Color {
	switch strings.ToLower(risk) {
	case "critical":
		return color.New(color.FgMagenta, color.Bold)
	case "high":
		return color.New(color.FgHiRed)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgWhite)
	}
}

func printKeywordResult(result KeywordResult, successPrinter *color.Color) {
	riskPrinter := getRiskPrinter(result.Risk)

	fmt.Printf("- Found %s | Risk Level: ", result.Label)
	riskPrinter.Printf("%s\n", result.Risk)

	fmt.Println("  Match: ", result.EnvVariable)
	fmt.Printf("  Key:    ")
	successPrinter.Printf("%s\n", result.MatchedValue)
	fmt.Println("")
}

func calculateTotals(searches []Search) (int, map[string]int) {
	totalKeywords := 0
	totalRisks := make(map[string]int)

	for _, search := range searches {
		totalKeywords += len(search.Keywords)
		for _, result := range search.Keywords {
			totalRisks[result.Risk]++
		}
	}

	return totalKeywords, totalRisks
}

func printSummary(searches []Search, printers map[string]*color.Color) {
	totalKeywords, totalRisks := calculateTotals(searches)

	printers["title"].Println("====================")

	for _, search := range searches {
		printSearchResult(search, printers["title"], printers["success"])
	}

	printers["success"].Printf("Scraping complete! Found %d files with %d matches\n", 
		len(searches), totalKeywords)
	printers["critical"].Printf("Critical: %d\n", totalRisks["critical"])
	printers["error"].Printf("High: %d\n", totalRisks["high"])
	printers["warning"].Printf("Medium: %d\n", totalRisks["medium"])
	printers["success"].Printf("Low: %d\n", totalRisks["low"])
}

func initLogger() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}