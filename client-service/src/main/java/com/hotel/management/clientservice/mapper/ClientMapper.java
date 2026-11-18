package com.hotel.management.clientservice.mapper;

import com.hotel.management.clientservice.dto.CreateClientRequest;
import com.hotel.management.clientservice.dto.ClientResponse;
import com.hotel.management.clientservice.dto.UpdateClientRequest;
import com.hotel.management.clientservice.entity.Client;
import org.springframework.stereotype.Component;

@Component
public class ClientMapper {

    public Client toEntity(CreateClientRequest request) {
        return Client.builder()
            .firstName(request.firstName())
            .lastName(request.lastName())
            .email(request.email())
            .phone(request.phone())
            .cin(request.cin())
            .passportNumber(request.passportNumber())
            .nationality(request.nationality())
            .address(request.address())
            .birthDate(request.birthDate())
            .active(true)
            .build();
    }

    public void updateEntity(Client client, UpdateClientRequest request) {
        client.setFirstName(request.firstName());
        client.setLastName(request.lastName());
        client.setEmail(request.email());
        client.setPhone(request.phone());
        client.setCin(request.cin());
        client.setPassportNumber(request.passportNumber());
        client.setNationality(request.nationality());
        client.setAddress(request.address());
        client.setBirthDate(request.birthDate());
    }

    public ClientResponse toResponse(Client client) {
        return new ClientResponse(
            client.getId(),
            client.getFirstName(),
            client.getLastName(),
            client.getEmail(),
            client.getPhone(),
            client.getCin(),
            client.getPassportNumber(),
            client.getNationality(),
            client.getAddress(),
            client.getBirthDate(),
            client.getActive(),
            client.getCreatedAt(),
            client.getUpdatedAt()
        );
    }
}
