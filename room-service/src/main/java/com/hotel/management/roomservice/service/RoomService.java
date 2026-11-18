package com.hotel.management.roomservice.service;

import com.hotel.management.roomservice.dto.RoomRequest;
import com.hotel.management.roomservice.dto.RoomResponse;
import com.hotel.management.roomservice.dto.RoomStatsResponse;
import com.hotel.management.roomservice.entity.Room;
import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;
import com.hotel.management.roomservice.exception.ConflictException;
import com.hotel.management.roomservice.exception.ResourceNotFoundException;
import com.hotel.management.roomservice.mapper.RoomMapper;
import com.hotel.management.roomservice.repository.RoomRepository;
import com.hotel.management.roomservice.repository.RoomSpecification;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RoomService {

    private final RoomRepository roomRepository;
    private final RoomMapper roomMapper;

    @Transactional
    public RoomResponse createRoom(RoomRequest request) {
        // Règle métier : Le numéro de chambre doit être unique
        if (roomRepository.existsByNumber(request.number())) {
            throw new ConflictException("Room number already exists: " + request.number());
        }

        Room room = roomMapper.toEntity(request);
        Room savedRoom = roomRepository.save(room);

        return roomMapper.toResponse(savedRoom);
    }

    public List<RoomResponse> getAllRooms(String number, RoomType type, RoomStatus status, Integer floor, Integer capacity, Boolean active) {
        Boolean effectiveActive = (active != null) ? active : Boolean.TRUE;
        Specification<Room> spec = RoomSpecification.withFilters(number, type, status, floor, capacity, effectiveActive);
        return roomRepository.findAll(spec).stream()
            .map(roomMapper::toResponse)
            .collect(Collectors.toList());
    }

    public RoomStatsResponse getRoomStats() {
        long total = roomRepository.countByActiveTrue();
        long available = roomRepository.countByStatusAndActiveTrue(RoomStatus.AVAILABLE);
        long occupied = roomRepository.countByStatusAndActiveTrue(RoomStatus.OCCUPIED);
        long reserved = roomRepository.countByStatusAndActiveTrue(RoomStatus.RESERVED);
        long cleaning = roomRepository.countByStatusAndActiveTrue(RoomStatus.CLEANING);
        long maintenance = roomRepository.countByStatusAndActiveTrue(RoomStatus.MAINTENANCE);
        long outOfService = roomRepository.countByStatusAndActiveTrue(RoomStatus.OUT_OF_SERVICE);
        return new RoomStatsResponse(total, available, occupied, reserved, cleaning, maintenance, outOfService);
    }

    public RoomResponse getRoomById(Long id) {
        Room room = roomRepository.findById(id)
            .filter(Room::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));
        return roomMapper.toResponse(room);
    }

    @Transactional
    public RoomResponse updateRoom(Long id, RoomRequest request) {
        Room room = roomRepository.findById(id)
            .filter(Room::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));

        // Règle métier : Si on change le numéro, vérifier qu'il n'est pas déjà pris
        if (!room.getNumber().equals(request.number()) && roomRepository.existsByNumber(request.number())) {
            throw new ConflictException("Room number already exists: " + request.number());
        }

        room.setNumber(request.number());
        room.setFloor(request.floor());
        room.setType(request.type());
        room.setPricePerNight(request.pricePerNight());
        room.setCapacity(request.capacity());
        room.setStatus(request.status());
        room.setDescription(request.description());

        Room updatedRoom = roomRepository.save(room);
        return roomMapper.toResponse(updatedRoom);
    }

    @Transactional
    public void deleteRoom(Long id) {
        Room room = roomRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));

        // Règle métier : Suppression logique
        room.setActive(false);
        roomRepository.save(room);
    }

    @Transactional
    public RoomResponse updateRoomStatus(Long id, RoomStatus newStatus) {
        Room room = roomRepository.findById(id)
            .filter(Room::getActive)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));

        room.setStatus(newStatus);
        Room updatedRoom = roomRepository.save(room);
        return roomMapper.toResponse(updatedRoom);
    }

    public List<RoomResponse> getDisabledRooms() {
        return roomRepository.findByActiveFalse().stream()
            .map(roomMapper::toResponse)
            .collect(Collectors.toList());
    }

    @Transactional
    public void activateRoom(Long id) {
        Room room = roomRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));
        room.setActive(true);
        roomRepository.save(room);
    }

    @Transactional
    public void deactivateRoom(Long id) {
        Room room = roomRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Room", id));
        room.setActive(false);
        roomRepository.save(room);
    }

    public List<RoomResponse> getRooms(String number, RoomType type, RoomStatus status, Integer floor, Integer capacity) {
        return roomRepository.findWithFilters(number, type, status, floor, capacity).stream()
            .map(roomMapper::toResponse)
            .collect(Collectors.toList());
    }


}
