package stig

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func checkDirectoryAccess(path string) error {
	// Check if the path exists
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", path)
	} else if err != nil {
		return fmt.Errorf("error accessing directory: %v", err)
	}

	// Check if the path is a directory
	if !info.IsDir() {
		return fmt.Errorf("path exists but is not a directory: %s", path)
	}

	// Check read and write access
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no read access to directory: %s", path)
	}
	defer file.Close()

	return nil
}

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %v", err)
	}
	defer r.Close()

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	for _, fileEntry := range r.File {
		//fmt.Printf("Processing entry: %s\n", fileEntry.Name)
		path := filepath.Join(dest, fileEntry.Name)

		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		// If directory (explicitly), create and continue
		if fileEntry.FileInfo().IsDir() {
			fmt.Printf("Creating directory: %s\n", path)
			if err := os.MkdirAll(path, fileEntry.Mode()); err != nil {
				return fmt.Errorf("failed to create directory: %v", err)
			}
			continue
		}

		// For files, ensure the parent directory is created
		// Not all zip files exclusively advertise the directory within the file format
		// So we need to add this here to ensure the directories are created.

		parentDir := filepath.Dir(path)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory: %v", err)
		}

		// Extract file
		if err := extractAndWriteFile(fileEntry, path); err != nil {
			return fmt.Errorf("failed to extract file: %v", err)
		}
	}
	return nil
}

func extractAndWriteFile(fileEntry *zip.File, path string) error {
	rc, err := fileEntry.Open()
	if err != nil {
		return fmt.Errorf("failed to open zip content: %v", err)
	}
	defer rc.Close()

	destFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileEntry.Mode())
	if err != nil {
		return fmt.Errorf("failed to open or create file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, rc)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	//fmt.Printf("Extracted %s (%d bytes)\n", path, written)
	return nil
}

func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
