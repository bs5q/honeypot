package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/tucnak/telebot.v2"
)

type Honeypot struct {
	Port             int
	ResponseMessage  string
	ThreatIntelFeeds []string
	TelegramToken    string
	TelegramChatID   int64
	Bot              *telebot.Bot
}

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	var honeypot Honeypot
	if err := viper.Unmarshal(&honeypot); err != nil {
		log.Fatalf("Error unmarshalling config: %v", err)
	}

	honeypot.initTelegramBot()

	go honeypot.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	fmt.Println("\nShutting down honeypot...")
}

func (h *Honeypot) initTelegramBot() {
	bot, err := telebot.NewBot(telebot.Settings{
		Token: h.TelegramToken,
	})
	if err != nil {
		log.Fatalf("Error initializing Telegram bot: %v", err)
	}

	h.Bot = bot
	fmt.Println("Telegram bot initialized")
}

func (h *Honeypot) Start() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", h.Port))
	if err != nil {
		log.Fatalf("Failed to start honeypot: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Honeypot started on port %d\n", h.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go h.handleConnection(conn)
	}
}

func (h *Honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Printf("Connection from %s\n", conn.RemoteAddr())

	time.Sleep(2 * time.Second)

	conn.Write([]byte(h.ResponseMessage))

	h.detectAttackPattern(conn)
}

func (h *Honeypot) detectAttackPattern(conn net.Conn) {
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Error reading data: %v", err)
		return
	}

	fmt.Printf("Potential attack pattern detected: %s\n", string(buffer))

	h.checkThreatIntelFeeds(string(buffer))
}

func (h *Honeypot) checkThreatIntelFeeds(data string) {
	for _, feed := range h.ThreatIntelFeeds {
		if data == feed {
			fmt.Printf("Threat Intel Feed Match: %s\n", feed)

			h.logAlert(feed)
			h.sendWebhookAlert(feed)
		}
	}
}

func (h *Honeypot) logAlert(threat string) {
	fmt.Printf("Alert: Potential threat detected - %s\n", threat)
}

func (h *Honeypot) sendWebhookAlert(threat string) {
	_, err := h.Bot.Send(&telebot.User{ID: h.TelegramChatID}, fmt.Sprintf("🚨 Alert: Potential threat detected - %s", threat))
	if err != nil {
		log.Printf("Error sending Telegram message: %v", err)
	}
}
