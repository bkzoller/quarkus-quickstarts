/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acme.spring.web;

import org.springframework.security.access.prepost.PreAuthorize;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.SecurityIdentity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Optional;

@RestController
@RequestMapping("/greeting")
public class GreetingController {

    private final GreetingBean greetingBean;
    private final CurrentIdentityAssociation currentIdentityAssociation;

    public GreetingController(GreetingBean greetingBean, CurrentIdentityAssociation currentIdentityAssociation) {
        this.greetingBean = greetingBean;
        this.currentIdentityAssociation = currentIdentityAssociation;
    }

    @PreAuthorize("permitAll()")
    @GetMapping("/{name}")
    public Greeting hello(@PathVariable(name = "name") String name) {
        String user = Optional.ofNullable(currentIdentityAssociation.getIdentity())
                .map(SecurityIdentity::getPrincipal)
                .map(Principal::getName)
                .orElse(name);
        return new Greeting(greetingBean.greet(user));
    }
}
