package com.hotel.management.roomservice.mapper;

import com.hotel.management.roomservice.dto.RoomRequest;
import com.hotel.management.roomservice.dto.RoomResponse;
import com.hotel.management.roomservice.entity.Room;
import org.springframework.stereotype.Component;

@Component
public class RoomMapper {

    public Room toEntity(RoomRequest request) {
        return Room.builder()
            .number(request.number())
            .floor(request.floor())
            .type(request.type())
            .pricePerNight(request.pricePerNight())
            .capacity(request.capacity())
            .status(request.status())
            .description(request.description())
            .active(true) // Une chambre est active par défaut à la création
            .build();
    }

    public RoomResponse toResponse(Room room) {
        return new RoomResponse(
            room.getId(),
            room.getNumber(),
            room.getFloor(),
            room.getType(),
            room.getPricePerNight(),
            room.getCapacity(),
            room.getStatus(),
            room.getDescription(),
            room.getActive(),
            room.getCreatedAt(),
            room.getUpdatedAt()
        );
    }
}
