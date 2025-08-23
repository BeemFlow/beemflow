package event

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/beemflow/beemflow/config"
)

func TestNewInProcEventBus(t *testing.T) {
	bus := NewInProcEventBus()
	if bus == nil {
		t.Error("expected non-nil event bus")
	}
}

func TestPublishSubscribeNoop(t *testing.T) {
	bus := NewInProcEventBus()
	err := bus.Publish("topic", "message")
	if err != nil {
		t.Errorf("Publish failed: %v", err)
	}
}

func TestEventBus_RoundTrip(t *testing.T) {
	bus := NewInProcEventBus()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received any
	var wg sync.WaitGroup
	wg.Add(1)

	bus.Subscribe(ctx, "test-topic", func(payload any) {
		received = payload
		wg.Done()
	})

	// Give subscriber time to set up
	time.Sleep(10 * time.Millisecond)

	err := bus.Publish("test-topic", "hello world")
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	wg.Wait()

	if received != "hello world" {
		t.Errorf("expected 'hello world', got %v", received)
	}
}

func TestNewEventBusFromConfig_Memory(t *testing.T) {
	cfg := &config.EventConfig{Driver: "memory"}
	bus, err := NewEventBusFromConfig(cfg)
	if err != nil {
		t.Errorf("NewEventBusFromConfig failed: %v", err)
	}
	if bus == nil {
		t.Error("expected non-nil event bus")
	}
}

func TestNewEventBusFromConfig_NATS(t *testing.T) {
	cfg := &config.EventConfig{
		Driver: "nats",
		URL:    "nats://localhost:4222",
	}
	_, err := NewEventBusFromConfig(cfg)
	if err == nil {
		t.Skip("NATS available - skipping error test")
	}
	t.Logf("NATS not available or error: %v", err)
}

func TestNewEventBusFromConfig_Unknown(t *testing.T) {
	cfg := &config.EventConfig{Driver: "unknown"}
	bus, err := NewEventBusFromConfig(cfg)
	if err == nil {
		t.Error("Expected error for unknown driver")
	}
	if bus != nil {
		t.Error("Expected nil event bus for unknown driver")
	}
}

// Test comprehensive Publish functionality
func TestWatermillEventBus_Publish_AllPayloadTypes(t *testing.T) {
	bus := NewWatermillInMemBus()

	testCases := []struct {
		name    string
		payload any
	}{
		{"string payload", "hello world"},
		{"byte slice payload", []byte("hello bytes")},
		{"map payload", map[string]any{"key": "value", "number": 42}},
		{"int payload", 123},
		{"float payload", 3.14},
		{"bool payload", true},
		{"nil payload", nil},
		{"complex map", map[string]any{
			"nested": map[string]any{"deep": "value"},
			"array":  []any{1, 2, 3},
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := bus.Publish("test-topic", tc.payload)
			if err != nil {
				t.Errorf("Publish failed for %s: %v", tc.name, err)
			}
		})
	}
}

// Test Publish with invalid JSON map
func TestWatermillEventBus_Publish_InvalidJSON(t *testing.T) {
	bus := NewWatermillInMemBus()

	// Create a map with a value that can't be marshaled to JSON
	invalidMap := map[string]any{
		"valid":   "value",
		"invalid": make(chan int), // channels can't be marshaled to JSON
	}

	err := bus.Publish("test-topic", invalidMap)
	if err == nil {
		t.Error("Expected error for invalid JSON map")
	}
}

// Test comprehensive Subscribe functionality
func TestWatermillEventBus_Subscribe_AllPayloadTypes(t *testing.T) {
	bus := NewWatermillInMemBus()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testCases := []struct {
		name            string
		publishPayload  any
		expectedPayload any
	}{
		{"string", "hello world", "hello world"},
		{"integer as string", "123", 123}, // Should be parsed as int
		{"json map", map[string]any{"key": "value"}, map[string]any{"key": "value"}},
		{"byte slice", []byte("hello bytes"), "hello bytes"},
		{"complex json", map[string]any{
			"nested": map[string]any{"deep": "value"},
			"number": float64(42), // JSON numbers become float64
		}, map[string]any{
			"nested": map[string]any{"deep": "value"},
			"number": float64(42),
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var received any
			var wg sync.WaitGroup
			wg.Add(1)

			topic := "test-" + tc.name

			bus.Subscribe(ctx, topic, func(payload any) {
				received = payload
				wg.Done()
			})

			// Give subscriber time to set up
			time.Sleep(10 * time.Millisecond)

			err := bus.Publish(topic, tc.publishPayload)
			if err != nil {
				t.Fatalf("Publish failed: %v", err)
			}

			wg.Wait()

			// Compare based on type
			switch expected := tc.expectedPayload.(type) {
			case map[string]any:
				receivedMap, ok := received.(map[string]any)
				if !ok {
					t.Errorf("Expected map, got %T: %v", received, received)
					return
				}
				if !mapsEqual(expected, receivedMap) {
					t.Errorf("Expected %v, got %v", expected, received)
				}
			default:
				if received != tc.expectedPayload {
					t.Errorf("Expected %v (%T), got %v (%T)", tc.expectedPayload, tc.expectedPayload, received, received)
				}
			}
		})
	}
}

// Test Subscribe with context cancellation
func TestWatermillEventBus_Subscribe_ContextCancellation(t *testing.T) {
	bus := NewWatermillInMemBus()
	ctx, cancel := context.WithCancel(context.Background())

	var received bool
	bus.Subscribe(ctx, "test-topic", func(payload any) {
		received = true
	})

	// Give subscriber time to set up
	time.Sleep(10 * time.Millisecond)

	// Cancel context
	cancel()

	// Give time for goroutine to exit
	time.Sleep(10 * time.Millisecond)

	// Publish after cancellation - should not be received
	err := bus.Publish("test-topic", "message")
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Give time for potential message processing
	time.Sleep(10 * time.Millisecond)

	if received {
		t.Error("Message should not be received after context cancellation")
	}
}

// Test Subscribe with channel close
func TestWatermillEventBus_Subscribe_ChannelClose(t *testing.T) {
	bus := NewWatermillInMemBus()
	ctx := context.Background()

	var messageCount int
	var wg sync.WaitGroup
	wg.Add(1)

	bus.Subscribe(ctx, "test-topic", func(payload any) {
		messageCount++
		if messageCount == 1 {
			wg.Done()
		}
	})

	// Give subscriber time to set up
	time.Sleep(10 * time.Millisecond)

	// Publish a message
	err := bus.Publish("test-topic", "message1")
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	wg.Wait()

	if messageCount != 1 {
		t.Errorf("Expected 1 message, got %d", messageCount)
	}
}

// Test NewWatermillNATSBUS error cases
func TestNewWatermillNATSBUS_ErrorCases(t *testing.T) {
	// Test with invalid configuration
	_, err := NewWatermillNATSBUS("", "", "")
	if err == nil {
		t.Error("Expected error for empty NATS configuration")
	}

	// Test with invalid URL
	_, err = NewWatermillNATSBUS("test-cluster", "test-client", "invalid-url")
	if err == nil {
		t.Error("Expected error for invalid NATS URL")
	}
}

// Test NewEventBusFromConfig with nil config
func TestNewEventBusFromConfig_NilConfig(t *testing.T) {
	bus, err := NewEventBusFromConfig(nil)
	if err != nil {
		t.Errorf("NewEventBusFromConfig with nil config should not error: %v", err)
	}
	if bus == nil {
		t.Error("Expected non-nil event bus for nil config")
	}
}

// Test NewEventBusFromConfig with empty config
func TestNewEventBusFromConfig_EmptyConfig(t *testing.T) {
	cfg := &config.EventConfig{}
	bus, err := NewEventBusFromConfig(cfg)
	if err != nil {
		t.Errorf("NewEventBusFromConfig with empty config should not error: %v", err)
	}
	if bus == nil {
		t.Error("Expected non-nil event bus for empty config")
	}
}

// Test Subscribe error handling
func TestWatermillEventBus_Subscribe_SubscribeError(t *testing.T) {
	// This test is harder to trigger since we'd need to mock the subscriber
	// For now, we'll test the normal case and rely on integration tests for error cases
	bus := NewWatermillInMemBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// This should not panic or error
	bus.Subscribe(ctx, "test-topic", func(payload any) {
		// Handler function
	})

	// Give time for subscription setup
	time.Sleep(10 * time.Millisecond)
}

// Helper function to compare maps
func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok {
			return false
		} else {
			switch av := v.(type) {
			case map[string]any:
				if bvm, ok := bv.(map[string]any); !ok {
					return false
				} else if !mapsEqual(av, bvm) {
					return false
				}
			default:
				if av != bv {
					return false
				}
			}
		}
	}
	return true
}
