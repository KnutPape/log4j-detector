// Copyright (c) 2021- Stripe, Inc. (https://stripe.com)
// This code is licensed under MIT license (see LICENSE-MIT for details)

// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jar

import (
	"testing"
)

func TestVersionFromJARFileName(t *testing.T) {
	_, result1 := versionFromJARFileName("\\\\?\\C:\\Users\\Pape\\.m2\\repository\\org\\springframework\\spring-jcl\\5.3.15\\spring-jcl-5.3.15.jar")

	if "5.3.15" != result1 {
		t.Errorf("Didn't Expected Version! %s", result1)
	}

	_, result2 := versionFromJARFileName("\\\\?\\C:\\Users\\Pape\\.m2\\repository\\org\\unbescape\\unbescape\\1.1.6.RELEASE\\unbescape-1.1.6.RELEASE.jar")

	if "1.1.6.RELEASE" != result2 {
		t.Errorf("Didn't Expected Version! %s", result2)
	}

}
