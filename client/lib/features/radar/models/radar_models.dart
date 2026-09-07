import 'dart:typed_data';

/// Represents a peer node discovered over the local enclave mesh or signaling channel
class RadarPeer {
  final String uuid;
  final String displayName;
  final String email;
  final String platform;
  final int pingMs;
  final bool isSimulated;
  final double orbitRadius;
  final double initialPhase;
  final double floatSpeed;

  const RadarPeer({
    required this.uuid,
    required this.displayName,
    required this.email,
    required this.platform,
    this.pingMs = 18,
    this.isSimulated = false,
    this.orbitRadius = 140.0,
    this.initialPhase = 0.0,
    this.floatSpeed = 1.0,
  });

  RadarPeer copyWith({
    String? uuid,
    String? displayName,
    String? email,
    String? platform,
    int? pingMs,
    bool? isSimulated,
    double? orbitRadius,
    double? initialPhase,
    double? floatSpeed,
  }) {
    return RadarPeer(
      uuid: uuid ?? this.uuid,
      displayName: displayName ?? this.displayName,
      email: email ?? this.email,
      platform: platform ?? this.platform,
      pingMs: pingMs ?? this.pingMs,
      isSimulated: isSimulated ?? this.isSimulated,
      orbitRadius: orbitRadius ?? this.orbitRadius,
      initialPhase: initialPhase ?? this.initialPhase,
      floatSpeed: floatSpeed ?? this.floatSpeed,
    );
  }
}

/// A securely sealed file asset attached to a P2P chat message
class P2PFileAttachment {
  final String fileId;
  final String fileName;
  final int fileSizeBytes;
  final String sha256Hash;
  final String c2paManifestUri;
  final Uint8List? bytes;
  final double progress; // 0.0 to 1.0
  final bool isCompleted;
  final bool isSealed;
  final String? localFilePath;
  final bool isVoiceNote;
  final bool isLiveRecorded;
  final int durationSeconds;

  const P2PFileAttachment({
    required this.fileId,
    required this.fileName,
    required this.fileSizeBytes,
    required this.sha256Hash,
    required this.c2paManifestUri,
    this.bytes,
    this.progress = 0.0,
    this.isCompleted = false,
    this.isSealed = true,
    this.localFilePath,
    this.isVoiceNote = false,
    this.isLiveRecorded = false,
    this.durationSeconds = 0,
  });

  P2PFileAttachment copyWith({
    String? fileId,
    String? fileName,
    int? fileSizeBytes,
    String? sha256Hash,
    String? c2paManifestUri,
    Uint8List? bytes,
    double? progress,
    bool? isCompleted,
    bool? isSealed,
    String? localFilePath,
    bool? isVoiceNote,
    bool? isLiveRecorded,
    int? durationSeconds,
  }) {
    return P2PFileAttachment(
      fileId: fileId ?? this.fileId,
      fileName: fileName ?? this.fileName,
      fileSizeBytes: fileSizeBytes ?? this.fileSizeBytes,
      sha256Hash: sha256Hash ?? this.sha256Hash,
      c2paManifestUri: c2paManifestUri ?? this.c2paManifestUri,
      bytes: bytes ?? this.bytes,
      progress: progress ?? this.progress,
      isCompleted: isCompleted ?? this.isCompleted,
      isSealed: isSealed ?? this.isSealed,
      localFilePath: localFilePath ?? this.localFilePath,
      isVoiceNote: isVoiceNote ?? this.isVoiceNote,
      isLiveRecorded: isLiveRecorded ?? this.isLiveRecorded,
      durationSeconds: durationSeconds ?? this.durationSeconds,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'fileId': fileId,
      'fileName': fileName,
      'fileSizeBytes': fileSizeBytes,
      'sha256Hash': sha256Hash,
      'c2paManifestUri': c2paManifestUri,
      'isSealed': isSealed,
      'isVoiceNote': isVoiceNote,
      'isLiveRecorded': isLiveRecorded,
      'durationSeconds': durationSeconds,
    };
  }

  factory P2PFileAttachment.fromJson(Map<String, dynamic> json) {
    return P2PFileAttachment(
      fileId: json['fileId']?.toString() ?? '',
      fileName: json['fileName']?.toString() ?? 'sealed_asset.bin',
      fileSizeBytes: (json['fileSizeBytes'] as num?)?.toInt() ?? 0,
      sha256Hash: json['sha256Hash']?.toString() ?? '',
      c2paManifestUri: json['c2paManifestUri']?.toString() ?? '',
      isSealed: json['isSealed'] == true,
      isVoiceNote: json['isVoiceNote'] == true,
      isLiveRecorded: json['isLiveRecorded'] == true,
      durationSeconds: (json['durationSeconds'] as num?)?.toInt() ?? 0,
    );
  }
}

/// Message in the encrypted P2P chat channel
class P2PChatMessage {
  final String id;
  final String senderId;
  final String senderName;
  final String text;
  final DateTime timestamp;
  final bool isSelf;
  final P2PFileAttachment? fileAttachment;
  final bool isSystemNotice;
  final bool isSeen;
  final DateTime? seenAt;
  final String? replyToId;
  final String? replyToSender;
  final String? replyToText;

  const P2PChatMessage({
    required this.id,
    required this.senderId,
    required this.senderName,
    required this.text,
    required this.timestamp,
    required this.isSelf,
    this.fileAttachment,
    this.isSystemNotice = false,
    this.isSeen = false,
    this.seenAt,
    this.replyToId,
    this.replyToSender,
    this.replyToText,
  });

  P2PChatMessage copyWith({
    String? id,
    String? senderId,
    String? senderName,
    String? text,
    DateTime? timestamp,
    bool? isSelf,
    P2PFileAttachment? fileAttachment,
    bool? isSystemNotice,
    bool? isSeen,
    DateTime? seenAt,
    String? replyToId,
    String? replyToSender,
    String? replyToText,
  }) {
    return P2PChatMessage(
      id: id ?? this.id,
      senderId: senderId ?? this.senderId,
      senderName: senderName ?? this.senderName,
      text: text ?? this.text,
      timestamp: timestamp ?? this.timestamp,
      isSelf: isSelf ?? this.isSelf,
      fileAttachment: fileAttachment ?? this.fileAttachment,
      isSystemNotice: isSystemNotice ?? this.isSystemNotice,
      isSeen: isSeen ?? this.isSeen,
      seenAt: seenAt ?? this.seenAt,
      replyToId: replyToId ?? this.replyToId,
      replyToSender: replyToSender ?? this.replyToSender,
      replyToText: replyToText ?? this.replyToText,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'senderId': senderId,
      'senderName': senderName,
      'text': text,
      'timestamp': timestamp.toIso8601String(),
      'fileAttachment': fileAttachment?.toJson(),
      'isSystemNotice': isSystemNotice,
      'isSeen': isSeen,
      'seenAt': seenAt?.toIso8601String(),
      'replyToId': replyToId,
      'replyToSender': replyToSender,
      'replyToText': replyToText,
    };
  }

  factory P2PChatMessage.fromJson(Map<String, dynamic> json, {required bool isSelf}) {
    return P2PChatMessage(
      id: json['id']?.toString() ?? '',
      senderId: json['senderId']?.toString() ?? '',
      senderName: json['senderName']?.toString() ?? 'Peer',
      text: json['text']?.toString() ?? '',
      timestamp: json['timestamp'] != null
          ? DateTime.tryParse(json['timestamp'].toString()) ?? DateTime.now()
          : DateTime.now(),
      isSelf: isSelf,
      fileAttachment: json['fileAttachment'] != null
          ? P2PFileAttachment.fromJson(json['fileAttachment'] as Map<String, dynamic>)
          : null,
      isSystemNotice: json['isSystemNotice'] == true,
      isSeen: json['isSeen'] == true,
      seenAt: json['seenAt'] != null ? DateTime.tryParse(json['seenAt'].toString()) : null,
      replyToId: json['replyToId']?.toString(),
      replyToSender: json['replyToSender']?.toString(),
      replyToText: json['replyToText']?.toString(),
    );
  }
}
