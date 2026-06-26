package com.hotel.management.housekeepingservice.service.client;

import com.hotel.management.housekeepingservice.dto.external.StaffSummaryResponse;
import com.hotel.management.housekeepingservice.exception.HousekeepingBusinessException;
import com.hotel.management.housekeepingservice.exception.HousekeepingTaskNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.ResourceAccessException;

@Component
public class StaffClient {

    private final RestClient restClient;
    private final String staffServiceUrl;

    public StaffClient(
            RestClient.Builder restClientBuilder,
            @Value("${staff.service.url:${STAFF_SERVICE_URL:http://staff-service:8087}}") String staffServiceUrl
    ) {
        this.restClient = restClientBuilder.build();
        this.staffServiceUrl = staffServiceUrl;
    }

    public StaffSummaryResponse findSummaryById(Long employeeId) {
        try {
            StaffSummaryResponse response = restClient.get()
                    .uri(staffServiceUrl + "/api/staff/{employeeId}", employeeId)
                    .retrieve()
                    .body(StaffSummaryResponse.class);
            if (response != null) {
                return response;
            }
        } catch (HttpClientErrorException.NotFound exception) {
            throw new HousekeepingTaskNotFoundException("Staff member not found with id: " + employeeId);
        } catch (ResourceAccessException ignored) {
            // Temporary fallback while staff-service is not reachable in V1 demos.
            return new StaffSummaryResponse(employeeId, "Agent housekeeping " + employeeId, "HOUSEKEEPING", true);
        }

        throw new HousekeepingBusinessException("Staff service returned an empty response for staff member: " + employeeId);
    }
}
