package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/notify/webhook"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/zap"
)

var storageUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload a file to cloud storage",
	Long:  "Upload a local file to the active project's storage. Without --key, the file is stored under ugc/<basename> (matching POST /api/storage/upload-source). Pass --key to choose an explicit object key.",
	Args:  cobra.ExactArgs(1),
	RunE:  runStorageUpload,
}

func init() {
	storageUploadCmd.Flags().String("key", "", "Object key (default: ugc/<basename>)")
	storageUploadCmd.Flags().String("content-type", "", "Content-Type to set on the object")
	storageCmd.AddCommand(storageUploadCmd)
}

func runStorageUpload(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	srcPath := args[0]
	f, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", srcPath, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", srcPath, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory; upload accepts a single file", srcPath)
	}

	key, _ := cmd.Flags().GetString("key")
	if key == "" {
		key = storage.UGCKey(filepath.Base(srcPath))
	}
	contentType, _ := cmd.Flags().GetString("content-type")

	if err := sc.Upload(context.Background(), projectUUID, key, f, info.Size(), contentType); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	url := storage.StorageURL(projectUUID, key)
	fmt.Printf("%s Uploaded %s (%s)\n",
		terminal.SuccessSymbol(), terminal.Cyan(filepath.Base(srcPath)), terminal.HumanBytes(info.Size()))
	fmt.Printf("  Key: %s\n", terminal.Gray(key))
	fmt.Printf("  URL: %s\n", terminal.Gray(url))
	return nil
}

// uploadNativeScanResults pushes the run's artifacts to cloud storage when
// --upload-results asked for it, and fires the configured webhook.
//
// The upload's failure is returned, the webhook's is not, and the split is the
// point: --upload-results names an artifact the caller asked for, so a run that
// did not produce it did not finish the job. A webhook is a notification about
// work that already happened and cannot un-happen; failing the scan because a
// listener was down would be the wrong answer. opts.UploadResults is only ever
// set from the flag (scan_flags.go), so nothing here fires without being asked.
func uploadNativeScanResults(settings *config.Settings, opts *types.Options, repo *database.Repository) error {
	err := doUploadNativeScanResults(settings, opts, repo)
	webhook.FireNativeScan(settings, repo, opts.ScanUUID)
	return err
}

func doUploadNativeScanResults(settings *config.Settings, opts *types.Options, repo *database.Repository) error {
	if !opts.UploadResults {
		return nil
	}
	if !settings.Storage.IsEnabled() {
		return errors.New("--upload-results was requested but storage is not enabled in config")
	}

	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		return fmt.Errorf("create storage client for result upload: %w", err)
	}

	files := make(map[string]string)
	if opts.Output != "" {
		for _, format := range opts.OutputFormats {
			path := opts.OutputPathForFormat(format)
			arcName := filepath.Base(path)
			files[arcName] = path
		}
	}

	// Include the native scan's runtime.log when persist_logs is enabled and
	// the file exists on disk for this scan.
	runtimeLog := filepath.Join(
		settings.ScanningStrategy.ScanLogs.EffectiveSessionsDir(),
		opts.ScanUUID,
		config.RuntimeLogFilename,
	)
	if fi, err := os.Stat(runtimeLog); err == nil && !fi.IsDir() {
		files[config.RuntimeLogFilename] = runtimeLog
	}

	if len(files) == 0 {
		// Not a failure: a console-only run has nothing on disk to bundle.
		zap.L().Info("storage: no result files to upload")
		return nil
	}

	key := storage.NativeScanResultKey(opts.ScanUUID)
	storageURL, err := sc.BundleAndUploadFiles(context.Background(), opts.ProjectUUID, key, files)
	if err != nil {
		return fmt.Errorf("upload scan results: %w", err)
	}

	// The bytes are in storage; only the pointer to them failed to persist. The
	// artifact exists, so this stays a warning.
	if repo != nil {
		if updateErr := repo.UpdateScanStorageURL(context.Background(), opts.ScanUUID, storageURL); updateErr != nil {
			zap.L().Warn("Failed to update scan storage URL", zap.Error(updateErr))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Results uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(storageURL))
	return nil
}

func uploadAgenticScanResults(settings *config.Settings, projectUUID, agenticScanUUID, sessionDir string, repo *database.Repository) {
	if !settings.Storage.IsEnabled() {
		zap.L().Warn("--upload-results specified but storage is not enabled in config")
		return
	}

	if sessionDir == "" {
		return
	}

	sc, err := storage.NewClient(&settings.Storage)
	if err != nil {
		zap.L().Warn("Failed to create storage client for result upload", zap.Error(err))
		return
	}

	key := storage.AgenticScanResultKey(agenticScanUUID)
	storageURL, err := sc.BundleAndUploadResults(context.Background(), projectUUID, key, sessionDir)
	if err != nil {
		zap.L().Warn("Failed to upload agentic scan results", zap.Error(err))
		return
	}

	if repo != nil {
		if updateErr := repo.UpdateAgenticScanStorageURL(context.Background(), agenticScanUUID, storageURL); updateErr != nil {
			zap.L().Warn("Failed to update agentic scan storage URL", zap.Error(updateErr))
		}
	}

	fmt.Fprintf(os.Stderr, "  %s Results uploaded to %s\n", terminal.SuccessSymbol(), terminal.Gray(storageURL))
}
