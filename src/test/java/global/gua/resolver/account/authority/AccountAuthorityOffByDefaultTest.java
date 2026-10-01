/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.api.AccountAuthorityHeadController;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.TransparencyLog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Everything this phase adds is off unless a deployment turns it on, and off means absent: no bean, no mapped
 * path, nothing read or written, and above all no ACCOUNT_AUTHORITY leaf. This runs on the shipped defaults,
 * which is what both environments deploy, so the rollback for the whole feature is a flag rather than a release.
 *
 * <p>The leaf assertion is the one that costs something if it regresses. The roster version is the
 * transparency-log size and new-account fallback placement seeds on it (ADM-001 L6), so a build that appended
 * even one head leaf by default would move where new accounts are placed in every environment that deployed it.
 *
 * <p>Off also means the security chain is the chain that shipped before this phase: the paths are added to the
 * public allowlist under the same condition that maps the controller, so they answer the deny-by-default 401
 * rather than a 404 that only this phase could produce.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccountAuthorityOffByDefaultTest {

    @Autowired MockMvc mockMvc;
    @Autowired ApplicationContext context;
    @Autowired ResolverProperties props;
    @Autowired JdbcTransparencyLog transparencyLog;

    @Test
    void bothAccountAuthorityFlagsDefaultToFalse() {
        assertThat(props.getAccountAuthority().isEnabled()).isFalse();
        assertThat(props.getAccountAuthority().isIngestEnabled()).isFalse();
    }

    @Test
    void noAccountAuthorityBeanExists() {
        assertThat(context.getBeanNamesForType(AccountAuthorityHeadController.class)).isEmpty();
        assertThat(context.getBeanNamesForType(AccountAuthorityHeadService.class)).isEmpty();
        assertThat(context.getBeanNamesForType(AccountAuthorityHeadVerifier.class)).isEmpty();
        assertThat(context.getBeanNamesForType(JdbcAccountAuthorityHeadStore.class)).isEmpty();
    }

    @Test
    void noAccountAuthorityPathIsPermittedOrMapped() throws Exception {
        // 401, not 404: with the flags off these paths fall to deny-by-default exactly as they did before this
        // phase existed. A 404 would mean the allowlist entry outlived the controller it exists for.
        mockMvc.perform(post("/account/authority/heads").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"record\":\"AAAA\",\"signature\":\"AAAA\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/account/authority/heads/"
                        + AuthorityHeadFixtures.bootstrapAccountId("off-by-default")))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/account/authority/heads/"
                        + AuthorityHeadFixtures.bootstrapAccountId("off-by-default") + "/proof"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void noAccountAuthorityLeafIsEverAppended() {
        assertThat(transparencyLog.eventsOfType(TransparencyLog.ACCOUNT_AUTHORITY)).isEmpty();
    }

    @Test
    void resolveBehavesExactlyAsItDoesToday() throws Exception {
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"+5511987654321\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"));
    }
}
