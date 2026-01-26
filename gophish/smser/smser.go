package smser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/gophish/gophish/logger"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

// SMS Provider constants
const (
	ProviderTwilio  = "twilio"
	ProviderTextBee = "textbee"
)

// TwilioMessage contains Twilio-specific message data
type TwilioMessage struct {
	Client twilio.RestClient
	Params openapi.CreateMessageParams
}

// TextBeeMessage contains TextBee-specific message data
type TextBeeMessage struct {
	ApiKey   string
	DeviceId string
	To       string
	Message  string
}

// TextBeeRequest is the request body for TextBee API
type TextBeeRequest struct {
	Recipients []string `json:"recipients"`
	Message    string   `json:"message"`
}

// TextBeeResponse is the response from TextBee API
type TextBeeResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// SmsMessage is a generic container for SMS messages
type SmsMessage struct {
	Provider string
	Twilio   *TwilioMessage
	TextBee  *TextBeeMessage
}

// Smser is an interface that defines an object used to queue and
// send mailer.Sms instances.
type Smser interface {
	Start(ctx context.Context)
	Queue([]Sms)
}

// Sms is an interface that handles the common operations for sms messages
type Sms interface {
	Error(err error) error
	Success() error
	Generate(msg *TwilioMessage) error
	GenerateGeneric(msg *SmsMessage) error
	GetProvider() string
	Backoff(err error) error
}

// SmsWorker is the worker that receives slices of sms's
type SmsWorker struct {
	queue chan []Sms
}

// NewSmsWorker returns an instance of SmsWorker with the mail queue
// initialized.
func NewSmsWorker() *SmsWorker {
	return &SmsWorker{
		queue: make(chan []Sms),
	}
}

// Start launches the mail worker to begin listening on the Queue channel
// for new slices of Sms instances to process.
func (sw *SmsWorker) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case sms := <-sw.queue:
			go func(ctx context.Context, sms []Sms) {
				sendSms(ctx, sms)
			}(ctx, sms)
		}
	}
}

// Queue sends the provided mail to the internal queue for processing.
func (sw *SmsWorker) Queue(sms []Sms) {
	sw.queue <- sms
}

// sendSms attempts to send the provided Sms instances.
// If the context is cancelled before all of the sms are sent,
// sendSms just returns and does not modify those sms's.
func sendSms(ctx context.Context, sms []Sms) {
	for _, s := range sms {
		select {
		case <-ctx.Done():
			return
		default:
			break
		}

		provider := s.GetProvider()

		switch provider {
		case ProviderTextBee:
			// Generate TextBee message
			message := &SmsMessage{Provider: ProviderTextBee}
			err := s.GenerateGeneric(message)
			if err != nil {
				log.Warn(err)
				s.Error(err)
				continue
			}
			// Send via TextBee
			err = SendTextBeeSMS(message.TextBee)
			if err != nil {
				log.Warn(err)
				s.Backoff(err)
				continue
			}
			s.Success()

		case ProviderTwilio:
			fallthrough
		default:
			// Generate Twilio message (default/legacy behavior)
			message := &TwilioMessage{}
			err := s.Generate(message)
			if err != nil {
				log.Warn(err)
				s.Error(err)
				continue
			}
			// Send via Twilio
			_, err = message.Client.Api.CreateMessage(&message.Params)
			if err != nil {
				log.Warn(err)
				s.Backoff(err)
				continue
			}
			s.Success()
		}
	}
}

// SendTextBeeSMS sends an SMS via the TextBee API
func SendTextBeeSMS(msg *TextBeeMessage) error {
	if msg == nil {
		return fmt.Errorf("TextBee message is nil")
	}

	url := fmt.Sprintf("https://api.textbee.dev/api/v1/gateway/devices/%s/send-sms", msg.DeviceId)

	payload := TextBeeRequest{
		Recipients: []string{msg.To},
		Message:    msg.Message,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal TextBee request: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create TextBee request: %v", err)
	}

	req.Header.Set("x-api-key", msg.ApiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("TextBee API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read TextBee response: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("TextBee API returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Infof("TextBee SMS sent successfully to %s", msg.To)
	return nil
}
