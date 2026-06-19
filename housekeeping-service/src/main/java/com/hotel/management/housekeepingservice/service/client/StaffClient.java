package com.hotel.management.housekeepingservice.service.client;

import com.hotel.management.housekeepingservice.dto.external.StaffSummaryResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class StaffClient {

    private final RestClient restClient;
    private final String staffServiceUrl;

    public StaffClient(
            RestClient.Builder restClientBuilder,
            @Value("${staff.service.url:${STAFF_SERVICE_URL:http://staff-service:8084}}") String staffServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.staffServiceUrl = staffServiceUrl;
    }

    public StaffSummaryResponse findSummaryById(Long employeeId) {
        try {
            StaffSummaryResponse response = restClient.get()
                    .uri(staffServiceUrl + "/api/staff/{employeeId}/summary", employeeId)
                    .retrieve()
                    .body(StaffSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (RestClientException ignored) {
            // Temporary fallback while staff-service is not available.
        }

        return new StaffSummaryResponse(employeeId, "Agent housekeeping " + employeeId, "HOUSEKEEPING", true);
    }
}
