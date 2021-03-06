/*
 * Copyright (c) 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.google.api.services.samples.youtube.cmdline.data;

import com.google.api.services.samples.youtube.cmdline.Auth;
import com.google.common.collect.Lists;

import java.io.IOException;
import java.util.List;

public class Highlights {

    public static void main(String[] args) throws IOException {
        List<String> scopes = Lists.newArrayList("https://www.googleapis.com/auth/youtube");
        Auth.authorize(scopes, "credentials");
    }
}
