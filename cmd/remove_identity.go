package cmd

import (
	"github.com/spf13/cobra"

	"github.com/theaaf/radius-server/app"
)

var removeIdentityCmd = &cobra.Command{
	Use:   "remove-identity",
	Short: "removes a new identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		redis, _ := cmd.Flags().GetString("redis")
		name, _ := cmd.Flags().GetString("name")

		return app.RemoveIdentity(redis, name)
	}}

func init() {
	removeIdentityCmd.Flags().String("redis", "", "the Redis server to use for storage (required)")
	removeIdentityCmd.MarkFlagRequired("redis")

	removeIdentityCmd.Flags().String("name", "", "the name of the identity (required)")
	removeIdentityCmd.MarkFlagRequired("name")

	rootCmd.AddCommand(removeIdentityCmd)
}
