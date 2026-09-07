// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'network_providers.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

String _$signalingServiceHash() => r'8db5121287239b1dbb52fb9527844cc97717693c';

/// See also [signalingService].
@ProviderFor(signalingService)
final signalingServiceProvider = Provider<SignalingService>.internal(
  signalingService,
  name: r'signalingServiceProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$signalingServiceHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef SignalingServiceRef = ProviderRef<SignalingService>;
String _$webRtcServiceHash() => r'fd80b20c702d0c340a9d8a01f128c1f827c3ae99';

/// See also [webRtcService].
@ProviderFor(webRtcService)
final webRtcServiceProvider = Provider<WebRTCService>.internal(
  webRtcService,
  name: r'webRtcServiceProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$webRtcServiceHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef WebRtcServiceRef = ProviderRef<WebRTCService>;
String _$discoveredPeersNotifierHash() =>
    r'1f65170788dd4ec31fcd992ddfb862f35d0933ef';

/// See also [DiscoveredPeersNotifier].
@ProviderFor(DiscoveredPeersNotifier)
final discoveredPeersNotifierProvider = AutoDisposeNotifierProvider<
    DiscoveredPeersNotifier, List<Map<String, dynamic>>>.internal(
  DiscoveredPeersNotifier.new,
  name: r'discoveredPeersNotifierProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$discoveredPeersNotifierHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef _$DiscoveredPeersNotifier
    = AutoDisposeNotifier<List<Map<String, dynamic>>>;
String _$autoAcceptNotifierHash() =>
    r'64243ae01a29270584240d7e9feaaf1d6075773f';

/// See also [AutoAcceptNotifier].
@ProviderFor(AutoAcceptNotifier)
final autoAcceptNotifierProvider =
    NotifierProvider<AutoAcceptNotifier, bool>.internal(
  AutoAcceptNotifier.new,
  name: r'autoAcceptNotifierProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$autoAcceptNotifierHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef _$AutoAcceptNotifier = Notifier<bool>;
String _$incomingTransferNotifierHash() =>
    r'645581461b52c3a60be33b4f55c7b6c7f867aed6';

/// See also [IncomingTransferNotifier].
@ProviderFor(IncomingTransferNotifier)
final incomingTransferNotifierProvider = NotifierProvider<
    IncomingTransferNotifier, IncomingTransferRequest?>.internal(
  IncomingTransferNotifier.new,
  name: r'incomingTransferNotifierProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$incomingTransferNotifierHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef _$IncomingTransferNotifier = Notifier<IncomingTransferRequest?>;
String _$transferStatusNotifierHash() =>
    r'ed28ea340275eda461a2bcc8a794813bbce4cb58';

/// See also [TransferStatusNotifier].
@ProviderFor(TransferStatusNotifier)
final transferStatusNotifierProvider =
    NotifierProvider<TransferStatusNotifier, String>.internal(
  TransferStatusNotifier.new,
  name: r'transferStatusNotifierProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$transferStatusNotifierHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef _$TransferStatusNotifier = Notifier<String>;
String _$transferProgressNotifierHash() =>
    r'08165d57da7a69eed51d3c731a0bb4a9033f7e3d';

/// See also [TransferProgressNotifier].
@ProviderFor(TransferProgressNotifier)
final transferProgressNotifierProvider = AutoDisposeNotifierProvider<
    TransferProgressNotifier, AsyncValue<double>>.internal(
  TransferProgressNotifier.new,
  name: r'transferProgressNotifierProvider',
  debugGetCreateSourceHash: const bool.fromEnvironment('dart.vm.product')
      ? null
      : _$transferProgressNotifierHash,
  dependencies: null,
  allTransitiveDependencies: null,
);

typedef _$TransferProgressNotifier = AutoDisposeNotifier<AsyncValue<double>>;
// ignore_for_file: type=lint
// ignore_for_file: subtype_of_sealed_class, invalid_use_of_internal_member, invalid_use_of_visible_for_testing_member
