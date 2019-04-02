package cmd

import (
	"context"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/theaaf/radius-server/app"
)

var serveRADIUSCmd = &cobra.Command{
	Use:   "serve-radius",
	Short: "runs the RADIUS server",
	RunE: func(cmd *cobra.Command, args []string) error {
		sharedSecret, _ := cmd.Flags().GetString("shared-secret")
		redis, _ := cmd.Flags().GetString("redis")

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, os.Interrupt)
			<-ch
			logrus.Info("signal received; shutting down")
			cancel()
		}()

		return app.ServeRADIUS(ctx, sharedSecret, redis)
	}}

func init() {
	serveRADIUSCmd.Flags().String("shared-secret", "", "the shared secret to use for mutual authentication (required)")
	serveRADIUSCmd.MarkFlagRequired("shared-secret")

	serveRADIUSCmd.Flags().String("redis", "", "the Redis server to use for storage (required)")
	serveRADIUSCmd.MarkFlagRequired("redis")

	rootCmd.AddCommand(serveRADIUSCmd)
}
