package de.adorsys.oauth.tokenstore.mongodb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

/**
 * MongoDbProvider
 */
@SuppressWarnings("unused")
public class MongoDbProvider {

    private static final Logger LOG = LoggerFactory.getLogger(MongoDbProvider.class);

    @Produces @ApplicationScoped
    public MongoDatabase producesMongoDatabase() {
        String mongoUri = System.getProperty("oauth.mongodb.uri", "mongodb://localhost:27017");
        String mongoDb  = System.getProperty("oauth.mongodb.database", "oauth");
        try {
            MongoClientURI clientURI = new MongoClientURI(mongoUri);
            LOG.info("use {}, database '{}', collection '{}'", createLogUri(clientURI), mongoDb, MdbTokenStore.COLLECTION_NAME);
            MongoClient mongoClient = new MongoClient(clientURI);
            return mongoClient.getDatabase(mongoDb);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("ReplaceAllDot")
    private String createLogUri(MongoClientURI clientURI) {
        StringBuilder sb = new StringBuilder();
        String password = clientURI.getPassword() == null ? null : new String(clientURI.getPassword()).replaceAll(".", "x");
        String username = clientURI.getUsername();
        for (String host : clientURI.getHosts()) {
            sb.append("mongodb://");
            if (username != null) {
                sb.append(username);
                if (password != null) {
                    sb.append(':').append(password);
                }
                sb.append('@');
            }
            sb.append(host).append(" ");
        }

        return sb.toString();
    }

}
