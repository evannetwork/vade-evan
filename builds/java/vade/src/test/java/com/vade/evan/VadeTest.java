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
        String options = "{ \"identity\": \"did:evan:testcore:0xc88d707c2436fa3ce4a1e52d751469acae689fdb\","
                         +
                         " \"privateKey\": \"16bd56948ba09a626551b3f39093da305b347ef4ef2182b2e667dfa5aaa0d4cd\" }";
        String createResult = Vade.executeVade("did_create", didCreateArgs, options, null);
        String result = JsonPath.read(createResult, "$.response");
        assertNotNull(result);

        String[] didResolveArgs = {"did:evan:testcore:0xc88d707c2436fa3ce4a1e52d751469acae689fdb"};
        String resolveResult = Vade.executeVade("did_resolve", didResolveArgs, null, null);
        result = JsonPath.read(resolveResult, "$.response");
        assertNotNull(result);

        System.out.println(result);
    }
}
