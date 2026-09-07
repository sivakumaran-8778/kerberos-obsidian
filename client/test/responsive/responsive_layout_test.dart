import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:kerberos_client/features/auth/presentation/auth_screen.dart';
import 'package:kerberos_client/features/forensics/presentation/document_forensics_screen.dart';
import 'package:kerberos_client/features/radar/presentation/widgets/mentimeter_peer_mesh.dart';
import 'package:kerberos_client/features/radar/models/radar_models.dart';
import 'package:kerberos_client/features/verification/presentation/verification_page.dart';

void main() {
  final viewports = [
    const Size(320, 568),  // Ultra compact (iPhone SE 1st gen)
    const Size(360, 640),  // Standard mobile compact (Android)
    const Size(390, 844),  // iPhone 13/14 modern
    const Size(412, 915),  // Pixel 7 / Large mobile
    const Size(768, 1024), // Tablet / iPad
    const Size(1920, 1080),// Windows Desktop / Wide monitor
  ];

  group('Responsive Layout RenderFlex Overflow Verification', () {
    for (final size in viewports) {
      testWidgets('AuthScreen renders without overflow at ${size.width}x${size.height}', (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        await tester.pumpWidget(
          const ProviderScope(
            child: MaterialApp(
              home: AuthScreen(),
            ),
          ),
        );
        await tester.pump();

        expect(tester.takeException(), isNull);
      });

      testWidgets('MentimeterPeerMesh renders without overflow at ${size.width}x${size.height}', (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        final dummyPeers = [
          RadarPeer(
            uuid: 'peer-1',
            displayName: 'Station Alpha',
            email: 'alpha@kerberos.dev',
            platform: 'Windows Node',
            pingMs: 12,
          ),
          RadarPeer(
            uuid: 'peer-2',
            displayName: 'Station Beta',
            email: 'beta@kerberos.dev',
            platform: 'macOS Enclave',
            pingMs: 24,
          ),
        ];

        await tester.pumpWidget(
          ProviderScope(
            child: MaterialApp(
              home: Scaffold(
                body: MentimeterPeerMesh(
                  peers: dummyPeers,
                  myName: 'Test Node',
                  myPlatform: 'Flutter Test',
                  onPeerSelected: (_) {},
                  onRefresh: () {},
                ),
              ),
            ),
          ),
        );
        await tester.pump();

        expect(tester.takeException(), isNull);
      });

      testWidgets('DocumentForensicsScreen renders without overflow at ${size.width}x${size.height}', (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        await tester.pumpWidget(
          const ProviderScope(
            child: MaterialApp(
              home: Scaffold(
                body: DocumentForensicsScreen(),
              ),
            ),
          ),
        );
        await tester.pump();

        expect(tester.takeException(), isNull);
      });

      testWidgets('VerificationPage renders without overflow at ${size.width}x${size.height}', (tester) async {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1.0;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);

        await tester.pumpWidget(
          const ProviderScope(
            child: MaterialApp(
              home: Scaffold(
                body: VerificationPage(),
              ),
            ),
          ),
        );
        await tester.pump();

        expect(tester.takeException(), isNull);
      });
    }
  });
}
