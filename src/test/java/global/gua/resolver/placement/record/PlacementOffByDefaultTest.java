/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.api.PlacementRecordController;
import global.gua.resolver.config.ResolverProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Everything this phase adds is off unless a deployment turns it on, and off means absent: no bean, no
 * mapped path, no scheduled job, nothing read or written. This runs on the shipped defaults, which is what
 * both environments deploy, so the rollback for the whole feature is a flag rather than a release.
 *
 * <p>Off also means the security chain is the chain that shipped before this phase. The placement paths are
 * added to the public allowlist under the same condition that maps the controller, so with the flags off
 * they are not permitted, not merely unmapped, and they answer the deny-by-default 401 they have always
 * answered rather than a 404 that only this phase could produce.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PlacementOffByDefaultTest {

    @Autowired MockMvc mockMvc;
    @Autowired ApplicationContext context;
    @Autowired ResolverProperties props;

    @Test
    void bothPlacementFlagsDefaultToFalse() {
        assertThat(props.getPlacement().isEnabled()).isFalse();
        assertThat(props.getPlacement().isIngestEnabled()).isFalse();
    }

    @Test
    void noPlacementBeanExists() {
        assertThat(context.getBeanNamesForType(PlacementRecordController.class)).isEmpty();
        assertThat(context.getBeanNamesForType(PlacementRecordService.class)).isEmpty();
        assertThat(context.getBeanNamesForType(PlacementRecordVerifier.class)).isEmpty();
        assertThat(context.getBeanNamesForType(JdbcPlacementRecordStore.class)).isEmpty();
        assertThat(context.getBeanNamesForType(PlacementCheckpointService.class)).isEmpty();
        assertThat(context.getBeanNamesForType(PlacementRecordAuditor.class)).isEmpty();
        assertThat(context.getBeanNamesForType(PlacementMetrics.class)).isEmpty();
    }

    @Test
    void noPlacementPathIsPermittedOrMapped() throws Exception {
        // 401, not 404: with the flags off these paths fall to deny-by-default exactly as they did before
        // this phase existed. A 404 would mean the allowlist entry outlived the controller it exists for.
        mockMvc.perform(post("/placement/records").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"record\":\"AAAA\",\"signature\":\"AAAA\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/placement/records/"
                        + PlacementFixtures.genesisAccountId("off-by-default")))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/placement/records").queryParam("homeserverId", "dev"))
                .andExpect(status().isUnauthorized());
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
