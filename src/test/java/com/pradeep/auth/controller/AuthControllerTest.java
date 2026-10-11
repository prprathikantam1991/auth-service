package com.pradeep.auth.controller;

import com.pradeep.auth.client.UserServiceClient;
import com.pradeep.auth.service.FinanceHandoffCodeService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthControllerTest {

    @Test
    void doesNotCompleteLoginWhenInternalUserProvisioningFails() throws Exception {
        UserServiceClient userServiceClient = mock(UserServiceClient.class);
        OidcUser oidcUser = mock(OidcUser.class);
        when(oidcUser.getEmail()).thenReturn("person@example.com");
        when(oidcUser.getSubject()).thenReturn("google-subject");
        when(oidcUser.getFullName()).thenReturn("Example Person");
        when(oidcUser.getPicture()).thenReturn("https://example.com/picture.png");
        when(userServiceClient.createOrUpdateUser(
                "person@example.com", "google-subject", "Example Person", "https://example.com/picture.png"
        )).thenReturn(false);

        AuthController controller = new AuthController(userServiceClient, mock(FinanceHandoffCodeService.class));
        ReflectionTestUtils.setField(controller, "frontendUrl", "http://localhost:4200");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession();
        MockHttpServletResponse response = new MockHttpServletResponse();

        var result = controller.handleSuccess(oidcUser, request, response);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(response.getRedirectedUrl())
                .isEqualTo("http://localhost:4200/login?error=user_provisioning_failed");
        verify(userServiceClient).createOrUpdateUser(
                "person@example.com", "google-subject", "Example Person", "https://example.com/picture.png"
        );
    }
}
