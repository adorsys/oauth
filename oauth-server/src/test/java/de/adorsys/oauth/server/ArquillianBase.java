/**
 * Copyright (C) 2015 Daniel Straub, Sandro Sonntag, Christian Brandenstein, Francis Pouatcha (sso@adorsys.de, dst@adorsys.de, cbr@adorsys.de, fpo@adorsys.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.adorsys.oauth.server;

import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.runner.RunWith;

import com.nimbusds.oauth2.sdk.id.ClientID;

import java.io.File;
import java.net.URI;

/**
 * ArquillianBase
 */
@RunWith(Arquillian.class)
public abstract class ArquillianBase {


    static boolean trace = true;

    protected static WebArchive createTestWar() {
        return createTestWar("test.war");
    }

    protected static WebArchive createTestWar(String name) {

        File[] dependencies = Maven.configureResolver().workOffline(true).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve().withTransitivity().asFile();

        return ShrinkWrap.create(WebArchive.class, name)
                .addClass(ArquillianBase.class)
                .addPackages(true, "de.adorsys.oauth.server")
                .addAsLibraries(dependencies)
                .addAsWebInfResource("beans.xml")
                .addAsWebInfResource("jboss-web.xml")
                .addAsWebInfResource("web.xml")
                .addAsResource("persistence.xml", "META-INF/persistence.xml")
                ;
//        System.out.println(a.toString(true));
//        return a;
    }


    protected static EnterpriseArchive createEnterpriseArchive(Archive... archives) {
        File[] dependencies = Maven.configureResolver().workOffline(true).loadPomFromFile("pom.xml").importRuntimeDependencies()
                .resolve().withTransitivity().asFile();

        EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "test.ear")
                .addAsLibraries(dependencies);

        for (Archive archive : archives) {
            addModule(ear, archive);
        }

        if (trace) {
            System.out.println(ear.toString(true));
        }
        return ear;
    }

    private static void addModule(EnterpriseArchive ear, Archive archive) {
        if (archive == null) {
            return;
        }
        if (trace) {
            System.out.println(archive.toString(true));
        }
        ear.addAsModule(archive);
    }

    protected URI getAuthEndpoint() {
        try {
            return new URI("http://localhost:8180/api/auth");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
    
    protected URI getTokenEndpoint() {
        try {
            return new URI("http://localhost:8180/api/token");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    protected URI getUserInfoEndpoint() {
        try {
            return new URI("http://localhost:8180/api/userinfo");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    protected URI getRedirect(String redirect) {
        try {
            return new URI("http://localhost:8180/api/" + redirect);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
    
    protected ClientID getClientID() {
        return new ClientID("test");
        
    }
}
