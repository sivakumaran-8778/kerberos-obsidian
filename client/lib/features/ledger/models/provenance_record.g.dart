// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'provenance_record.dart';

// **************************************************************************
// TypeAdapterGenerator
// **************************************************************************

class ProvenanceRecordAdapter extends TypeAdapter<ProvenanceRecord> {
  @override
  final int typeId = 0;

  @override
  ProvenanceRecord read(BinaryReader reader) {
    final numOfFields = reader.readByte();
    final fields = <int, dynamic>{
      for (int i = 0; i < numOfFields; i++) reader.readByte(): reader.read(),
    };
    return ProvenanceRecord(
      id: fields[0] as String,
      originalFileHash: fields[1] as String,
      c2paManifestUri: fields[2] as String,
      timestamp: fields[3] as DateTime,
      signature: fields[4] as String,
      filePath: fields[5] as String,
    );
  }

  @override
  void write(BinaryWriter writer, ProvenanceRecord obj) {
    writer
      ..writeByte(6)
      ..writeByte(0)
      ..write(obj.id)
      ..writeByte(1)
      ..write(obj.originalFileHash)
      ..writeByte(2)
      ..write(obj.c2paManifestUri)
      ..writeByte(3)
      ..write(obj.timestamp)
      ..writeByte(4)
      ..write(obj.signature)
      ..writeByte(5)
      ..write(obj.filePath);
  }

  @override
  int get hashCode => typeId.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ProvenanceRecordAdapter &&
          runtimeType == other.runtimeType &&
          typeId == other.typeId;
}
