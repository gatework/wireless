// Package bootstrap resolves configuration, credentials and inventory into
// the objects the commands use: the vendor, the snapshot store, the
// connector dialer, the diagnoser and the health inspector.
//
// Precedence is process environment over the credentials file over
// wireless.yml over defaults. Credentials are read only from the
// environment or a 0600 credentials file, never from wireless.yml.
package bootstrap
