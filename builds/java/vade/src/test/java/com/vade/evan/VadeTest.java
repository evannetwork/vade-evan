package com.vade.evan;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Unit test for simple App.
 */
class VadeTest {

    @Test
    void testApp() {
        String[] didCreateArgs = {"did:evan:testcore"};
        String options = "{ \"identity\": \"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906\","
                         +
                         " \"privateKey\": \"dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106\" }";
        String createResult = Vade.executeVade("did_create", didCreateArgs, options, null);
        String result = JsonPath.read(createResult, "$.response");
        assertNotNull(result);

        String[] didResolveArgs = {"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906"};
        String resolveResult = Vade.executeVade("did_resolve", didResolveArgs, null, null);
        result = JsonPath.read(resolveResult, "$.response");
        assertNotNull(result);
    }
}
