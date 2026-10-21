package ui

import (
	"fmt"
	"math/rand"

	"github.com/fatih/color"
)

var motdRed = color.New(color.FgHiRed)

var motds = []string{
	"ratk0wn by skver303",
	"каллкод удали пж",
	"get ratkowned",
	"шакализация грузiтся... 69%",
	"t.me/ratkown",
}

func RandomMOTD() string {
	return motds[rand.Intn(len(motds))]
}

func PrintBanner(nowStr string) {
	motdRed.Printf("[%s] ratk0wn ", nowStr)
	fmt.Printf("- %s\n", RandomMOTD())
}
