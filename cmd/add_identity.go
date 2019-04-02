package cmd

import (
	"github.com/spf13/cobra"

	"github.com/theaaf/radius-server/app"
)

var addIdentityCmd = &cobra.Command{
	Use:   "add-identity",
	Short: "adds a new identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		redis, _ := cmd.Flags().GetString("redis")
		name, _ := cmd.Flags().GetString("name")
		password, _ := cmd.Flags().GetString("password")

		return app.AddIdentity(redis, name, password)
	}}

func init() {
	addIdentityCmd.Flags().String("redis", "", "the Redis server to use for storage (required)")
	addIdentityCmd.MarkFlagRequired("redis")

	addIdentityCmd.Flags().String("name", "", "the name of the identity (required)")
	addIdentityCmd.MarkFlagRequired("name")

	addIdentityCmd.Flags().String("password", "", "the password for the identity (required)")
	addIdentityCmd.MarkFlagRequired("password")

	rootCmd.AddCommand(addIdentityCmd)
}
