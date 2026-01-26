package gmapsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	BaseURL        = "https://cloud.gmapsextractor.com/api/v2/search"
	DefaultTimeout = 30 * time.Second
)

// Client is the API client for gmapsextractor.com
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
	}
}

// SearchRequest represents the API search request
type SearchRequest struct {
	Query    string `json:"q"`
	Page     int    `json:"page"`
	Location string `json:"ll,omitempty"` // Format: @lat,lng,zoomz (e.g., @23.0875893,112.3725638,11z)
	Language string `json:"hl,omitempty"` // e.g., "en"
	Country  string `json:"gl,omitempty"` // e.g., "us"
	Extra    bool   `json:"extra"`        // Include emails and social media links
}

// SearchResponse represents the API response
type SearchResponse struct {
	Status string        `json:"status"`
	Data   []PlaceResult `json:"data"`   // API returns "data" not "results"
	Error  string        `json:"error,omitempty"`
}

// PlaceResult represents a single place from the API
type PlaceResult struct {
	Name             string   `json:"name"`
	FullAddress      string   `json:"full_address"`
	Street           string   `json:"street"`
	Municipality     string   `json:"municipality"`
	Categories       string   `json:"categories"` // Comma-separated string
	Phone            string   `json:"phone"`
	Phones           string   `json:"phones"`
	Claimed          string   `json:"claimed"`
	AverageRating    float64  `json:"average_rating"`
	ReviewURL        string   `json:"review_url"`
	Latitude         float64  `json:"latitude"`
	Longitude        float64  `json:"longitude"`
	Website          string   `json:"website"`
	Domain           string   `json:"domain"`
	OpeningHours     string   `json:"opening_hours"`
	FeaturedImage    string   `json:"featured_image"`
	GoogleMapsURL    string   `json:"google_maps_url"`
	GoogleKnowledgeURL string `json:"google_knowledge_url"`
	CID              string   `json:"cid"`
	Kgmid            string   `json:"kgmid"`
	PlaceID          string   `json:"place_id"`
	Emails           []string `json:"emails"`
	FacebookLinks    []string `json:"facebook_links"`
	InstagramLinks   []string `json:"instagram_links"`
	LinkedinLinks    []string `json:"linkedin_links"`
	TwitterLinks     []string `json:"twitter_links"`
	YelpLinks        []string `json:"yelp_links"`
	YoutubeLinks     []string `json:"youtube_links"`
	PinterestLinks   []string `json:"pinterest_links"`
	TiktokLinks      []string `json:"tiktok_links"`
}

// Search performs a search using the API
func (c *Client) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, BaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	log.Printf("API response: %s", string(respBody))

	var searchResp SearchResponse
	if err := json.Unmarshal(respBody, &searchResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	log.Printf("API parsed %d results, status: %s", len(searchResp.Data), searchResp.Status)

	if searchResp.Error != "" {
		return nil, fmt.Errorf("API returned error: %s", searchResp.Error)
	}

	return &searchResp, nil
}

// SearchAll performs paginated search to get the desired number of results
func (c *Client) SearchAll(ctx context.Context, query, location, lang, country string, maxResults int, extra bool) ([]PlaceResult, error) {
	var allResults []PlaceResult
	page := 1
	resultsPerPage := 20 // API typically returns ~20 results per page

	for len(allResults) < maxResults {
		select {
		case <-ctx.Done():
			return allResults, ctx.Err()
		default:
		}

		req := SearchRequest{
			Query:    query,
			Page:     page,
			Location: location,
			Language: lang,
			Country:  country,
			Extra:    extra,
		}

		resp, err := c.Search(ctx, req)
		if err != nil {
			// If we have some results, return them instead of failing completely
			if len(allResults) > 0 {
				return allResults, nil
			}
			return nil, err
		}

		if len(resp.Data) == 0 {
			// No more results
			break
		}

		allResults = append(allResults, resp.Data...)
		page++

		// If we got fewer results than expected, we've reached the end
		if len(resp.Data) < resultsPerPage {
			break
		}

		// Small delay to respect rate limits (300 req/min = 5 req/sec)
		time.Sleep(250 * time.Millisecond)
	}

	// Trim to maxResults if we got more
	if len(allResults) > maxResults {
		allResults = allResults[:maxResults]
	}

	return allResults, nil
}
