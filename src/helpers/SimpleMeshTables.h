#pragma once

#include <Mesh.h>

#ifdef ESP32
  #include <FS.h>
#endif

#define MAX_PACKET_HASHES  256
#define MAX_PACKET_ACKS     64
#define BUCKET_PROBE_SLOTS   4   // Linear probing: check this many slots per bucket

class SimpleMeshTables : public mesh::MeshTables {
  uint8_t _hashes[MAX_PACKET_HASHES*MAX_HASH_SIZE];
  uint32_t _acks[MAX_PACKET_ACKS];
  int _next_ack_idx;
  uint32_t _direct_dups, _flood_dups;

  // Helper: compute bucket index from first 2 bytes of hash
  inline uint16_t hashToBucket(const uint8_t* hash) const {
    uint16_t bucket = ((uint16_t)hash[0] << 8) | hash[1];
    return bucket % MAX_PACKET_HASHES;
  }

public:
  SimpleMeshTables() {
    memset(_hashes, 0, sizeof(_hashes));
    memset(_acks, 0, sizeof(_acks));
    _next_ack_idx = 0;
    _direct_dups = _flood_dups = 0;
  }

#ifdef ESP32
  void restoreFrom(File f) {
    f.read(_hashes, sizeof(_hashes));
    f.read((uint8_t *) &_acks[0], sizeof(_acks));
    f.read((uint8_t *) &_next_ack_idx, sizeof(_next_ack_idx));
  }
  void saveTo(File f) {
    f.write(_hashes, sizeof(_hashes));
    f.write((const uint8_t *) &_acks[0], sizeof(_acks));
    f.write((const uint8_t *) &_next_ack_idx, sizeof(_next_ack_idx));
  }
#endif

  bool hasSeen(const mesh::Packet* packet) override {
    if (packet->getPayloadType() == PAYLOAD_TYPE_ACK) {
      uint32_t ack;
      memcpy(&ack, packet->payload, 4);
      for (int i = 0; i < MAX_PACKET_ACKS; i++) {
        if (ack == _acks[i]) {
          if (packet->isRouteDirect()) {
            _direct_dups++;   // keep some stats
          } else {
            _flood_dups++;
          }
          return true;
        }
      }

      _acks[_next_ack_idx] = ack;
      _next_ack_idx = (_next_ack_idx + 1) % MAX_PACKET_ACKS;  // cyclic table
      return false;
    }

    uint8_t hash[MAX_HASH_SIZE];
    packet->calculatePacketHash(hash);

    // O(1) bucket lookup using first 2 bytes of hash as index
    uint16_t bucket = hashToBucket(hash);

    // Linear probing: check BUCKET_PROBE_SLOTS consecutive slots
    int emptySlotIdx = -1;  // Track first empty slot for insertion
    for (int i = 0; i < BUCKET_PROBE_SLOTS; i++) {
      uint16_t probeIdx = (bucket + i) % MAX_PACKET_HASHES;
      uint8_t* slot = &_hashes[probeIdx * MAX_HASH_SIZE];

      // Check if this slot matches
      if (memcmp(hash, slot, MAX_HASH_SIZE) == 0) {
        if (packet->isRouteDirect()) {
          _direct_dups++;   // keep some stats
        } else {
          _flood_dups++;
        }
        return true;
      }

      // Track first empty slot for later insertion
      if (emptySlotIdx < 0) {
        bool isEmpty = true;
        for (int j = 0; j < MAX_HASH_SIZE; j++) {
          if (slot[j] != 0) { isEmpty = false; break; }
        }
        if (isEmpty) emptySlotIdx = probeIdx;
      }
    }

    // Not seen - store in first empty slot, or first probed slot if all full
    int insertIdx = (emptySlotIdx >= 0) ? emptySlotIdx : bucket;
    memcpy(&_hashes[insertIdx * MAX_HASH_SIZE], hash, MAX_HASH_SIZE);
    return false;
  }

  void clear(const mesh::Packet* packet) override {
    if (packet->getPayloadType() == PAYLOAD_TYPE_ACK) {
      uint32_t ack;
      memcpy(&ack, packet->payload, 4);
      for (int i = 0; i < MAX_PACKET_ACKS; i++) {
        if (ack == _acks[i]) {
          _acks[i] = 0;
          break;
        }
      }
    } else {
      uint8_t hash[MAX_HASH_SIZE];
      packet->calculatePacketHash(hash);

      // O(1) bucket lookup using first 2 bytes of hash as index
      uint16_t bucket = hashToBucket(hash);

      // Linear probing: check BUCKET_PROBE_SLOTS consecutive slots
      for (int i = 0; i < BUCKET_PROBE_SLOTS; i++) {
        uint16_t probeIdx = (bucket + i) % MAX_PACKET_HASHES;
        uint8_t* slot = &_hashes[probeIdx * MAX_HASH_SIZE];

        if (memcmp(hash, slot, MAX_HASH_SIZE) == 0) {
          memset(slot, 0, MAX_HASH_SIZE);
          break;  // Found and cleared, done
        }
      }
    }
  }

  uint32_t getNumDirectDups() const { return _direct_dups; }
  uint32_t getNumFloodDups() const { return _flood_dups; }

  void resetStats() { _direct_dups = _flood_dups = 0; }
};
