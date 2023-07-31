// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
)

func main() {
	out, err := os.Create("generated.go")
	if err != nil {
		failf("%v", err)
	}
	defer out.Close()
	data, err := ioutil.ReadFile("../../executor/common.h")
	if err != nil {
		failf("%v", err)
	}
	executorFilenames := []string{
		"common_linux.h",
		"common_akaros.h",
		"common_bsd.h",
		"common_fuchsia.h",
		"common_windows.h",
		"common_test.h",
		"common_kvm_amd64.h",
		"common_kvm_arm64.h",
		"common_usb.h",
		"common_usb_linux.h",
		"android/android_seccomp.h",
		"kvm.h",
		"kvm.S.h",
	}
	data = replaceIncludes(executorFilenames, "../../executor/", data)
	androidFilenames := []string{
		"arm64_app_policy.h",
		"arm_app_policy.h",
		"x86_64_app_policy.h",
		"x86_app_policy.h",
	}
	data = replaceIncludes(androidFilenames, "../../executor/android/", data)
	for _, remove := range []string{
		"(\n|^)\\s*//.*",
		"\\s*//.*",
	} {
		data = regexp.MustCompile(remove).ReplaceAll(data, nil)
	}
	fmt.Fprintf(out, "// AUTOGENERATED FILE FROM executor/*.h\n\n")
	fmt.Fprintf(out, "package csource\n\nvar commonHeader = `\n")
	out.Write(data)
	fmt.Fprintf(out, "`\n")
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func replaceIncludes(filenames []string, location string, data []byte) []byte {
	for _, include := range filenames {
		contents, err := ioutil.ReadFile(location + include)
		if err != nil {
			failf("%v", err)
		}
		replace := []byte("#include \"" + include + "\"")
		if bytes.Index(data, replace) == -1 {
			failf("can't find %v include", include)
		}
		data = bytes.Replace(data, replace, contents, -1)
	}
	return data
}