package com.hotel.management.clientservice.service;

import com.hotel.management.clientservice.dto.ClientResponse;
import com.hotel.management.clientservice.dto.CreateClientRequest;
import com.hotel.management.clientservice.dto.UpdateClientRequest;
import com.hotel.management.clientservice.entity.Client;
import com.hotel.management.clientservice.exception.BusinessException;
import com.hotel.management.clientservice.exception.ConflictException;
import com.hotel.management.clientservice.exception.ResourceNotFoundException;
import com.hotel.management.clientservice.mapper.ClientMapper;
import com.hotel.management.clientservice.repository.ClientRepository;
import com.hotel.management.clientservice.repository.ClientSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ClientService {

    private final ClientRepository clientRepository;
    private final ClientMapper clientMapper;

    @Transactional
    public ClientResponse createClient(CreateClientRequest request) {
        validateIdentification(request.email(), request.cin(), request.passportNumber(), request.phone());
        checkUniqueConstraintsOnCreate(request);

        Client client = clientMapper.toEntity(request);
        return clientMapper.toResponse(clientRepository.save(client));
    }

    public List<ClientResponse> getAllClients(String search, Boolean active) {
        Specification<Client> spec = ClientSpecification.withFilters(search, active);
        return clientRepository.findAll(spec).stream()
            .map(clientMapper::toResponse)
            .collect(Collectors.toList());
    }

    public ClientResponse getClientById(Long id) {
        Client client = clientRepository.findById(id)
            .filter(Client::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Client", id));
        return clientMapper.toResponse(client);
    }

    @Transactional
    public ClientResponse updateClient(Long id, UpdateClientRequest request) {
        Client client = clientRepository.findById(id)
            .filter(Client::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Client", id));

        validateIdentification(request.email(), request.cin(), request.passportNumber(), request.phone());
        checkUniqueConstraintsOnUpdate(id, request);

        clientMapper.updateEntity(client, request);
        return clientMapper.toResponse(clientRepository.save(client));
    }

    @Transactional
    public void deleteClient(Long id) {
        Client client = clientRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Client", id));
        // Suppression logique — règle métier §8.4
        client.setActive(false);
        clientRepository.save(client);
    }

    @Transactional
    public void activateClient(Long id) {
        Client client = clientRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Client", id));
        client.setActive(true);
        clientRepository.save(client);
    }

    @Transactional
    public void deactivateClient(Long id) {
        Client client = clientRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Client", id));
        client.setActive(false);
        clientRepository.save(client);
    }

    public ClientResponse getClientByEmail(String email) {
        Client client = clientRepository.findByEmail(email)
            .filter(Client::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Client", "email", email));
        return clientMapper.toResponse(client);
    }

    public List<ClientResponse> searchClients(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return clientRepository.findByActiveTrue().stream()
                .map(clientMapper::toResponse)
                .collect(Collectors.toList());
        }
        return clientRepository.search(keyword).stream()
            .map(clientMapper::toResponse)
            .collect(Collectors.toList());
    }

    // Au moins un moyen d'identification requis — règle métier §8.4
    private void validateIdentification(String email, String cin, String passportNumber, String phone) {
        boolean hasIdentification = (email != null && !email.isBlank())
            || (cin != null && !cin.isBlank())
            || (passportNumber != null && !passportNumber.isBlank())
            || (phone != null && !phone.isBlank());

        if (!hasIdentification) {
            throw new BusinessException("At least one identification must be provided: email, CIN, passport or phone");
        }
    }

    private void checkUniqueConstraintsOnCreate(CreateClientRequest request) {
        if (request.email() != null && !request.email().isBlank() && clientRepository.existsByEmail(request.email())) {
            throw new ConflictException("Email already exists: " + request.email());
        }
        if (request.cin() != null && !request.cin().isBlank() && clientRepository.existsByCin(request.cin())) {
            throw new ConflictException("CIN already exists: " + request.cin());
        }
        if (request.passportNumber() != null && !request.passportNumber().isBlank() && clientRepository.existsByPassportNumber(request.passportNumber())) {
            throw new ConflictException("Passport number already exists: " + request.passportNumber());
        }
    }

    private void checkUniqueConstraintsOnUpdate(Long id, UpdateClientRequest request) {
        if (request.email() != null && !request.email().isBlank() && clientRepository.existsByEmailAndIdNot(request.email(), id)) {
            throw new ConflictException("Email already exists: " + request.email());
        }
        if (request.cin() != null && !request.cin().isBlank() && clientRepository.existsByCinAndIdNot(request.cin(), id)) {
            throw new ConflictException("CIN already exists: " + request.cin());
        }
        if (request.passportNumber() != null && !request.passportNumber().isBlank() && clientRepository.existsByPassportNumberAndIdNot(request.passportNumber(), id)) {
            throw new ConflictException("Passport number already exists: " + request.passportNumber());
        }
    }
}
