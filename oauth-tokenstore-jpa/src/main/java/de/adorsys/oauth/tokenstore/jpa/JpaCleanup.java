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
package de.adorsys.oauth.tokenstore.jpa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.Schedule;
import javax.ejb.Singleton;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

/**
 * Created by cbr on 04.06.16.
 */
@Singleton
public class JpaCleanup {

    private static final Logger LOG = LoggerFactory.getLogger(JpaCleanup.class);

    @PersistenceContext(unitName = "oauth")
    private EntityManager entityManager;

    @Schedule(hour="1", persistent=false)
    public void doCleanup(){
        Object property = System.getProperty("oauth.doCleanup");

        if (property != null && ((String)property).equals("true")) {
            // 20 days
            LocalDate nowMinus20 = LocalDate.now().minusDays(20);
            Instant instant = nowMinus20.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant();
            Date date = Date.from(instant);

            LOG.info("Cleaning up tokens older than: " + date);

            int countAuthCode = entityManager.createQuery("delete from AuthCodeEntity ace where ace.created < :date")
                    .setParameter("date", date)
                    .executeUpdate();

            LOG.info("Deleted " + countAuthCode + " AuthCodeEntities");

            int countToken = entityManager.createQuery("delete from TokenEntity te where te.created < :date")
                    .setParameter("date", date)
                    .executeUpdate();

            LOG.info("Deleted " + countToken + " TokenEntity");

            int countLoginSession = entityManager.createQuery("delete from LoginSessionEntity lse where lse.created < :date")
                    .setParameter("date", date)
                    .executeUpdate();

            LOG.info("Deleted " + countLoginSession + " LoginSessionEntity");
        }
    }
}
