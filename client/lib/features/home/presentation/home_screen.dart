import 'package:flutter/material.dart';
import '../../../shared/widgets/neomorphic_container.dart';
import '../../../shared/widgets/neomorphic_button.dart';
import '../../dashboard/presentation/dashboard_screen.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          physics: const BouncingScrollPhysics(),
          child: Column(
            children: [
              const _TopNavigationBar(),
              const SizedBox(height: 64),
              const _HeroSection(),
              const SizedBox(height: 128),
              const _FeatureGrid(),
              const SizedBox(height: 128),
              
              // Footer
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(32),
                child: const Text(
                  '© 2026 PROJECT KERBEROS. ZERO-TRUST ARCHITECTURE.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.black26, fontSize: 12, letterSpacing: 2, fontFamily: 'monospace'),
                ),
              )
            ],
          ),
        ),
      ),
    );
  }
}

class _TopNavigationBar extends StatelessWidget {
  const _TopNavigationBar();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 64, vertical: 32),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              NeomorphicContainer(
                width: 48,
                height: 48,
                borderRadius: 12,
                padding: EdgeInsets.zero,
                child: const Center(child: Icon(Icons.fingerprint, color: kAccentColor)),
              ),
              const SizedBox(width: 24),
              Text(
                'KERBEROS',
                style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.w900,
                  letterSpacing: 8,
                ),
              ),
            ],
          ),
          Row(
            children: [
              const _NavGhostButton(label: 'ARCHITECTURE'),
              const SizedBox(width: 32),
              const _NavGhostButton(label: 'PROTOCOL'),
              const SizedBox(width: 48),
              NeomorphicButton(
                onTap: () => _launchApp(context),
                child: const Text('LAUNCH APP', style: TextStyle(color: kAccentColor, fontWeight: FontWeight.bold)),
              )
            ],
          )
        ],
      ),
    );
  }
}

class _NavGhostButton extends StatelessWidget {
  final String label;
  const _NavGhostButton({required this.label});

  @override
  Widget build(BuildContext context) {
    return Text(
      label,
      style: const TextStyle(
        color: kTextColor,
        fontWeight: FontWeight.w600,
        letterSpacing: 1.5,
        fontSize: 14,
      ),
    );
  }
}

class _HeroSection extends StatelessWidget {
  const _HeroSection();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 64),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          // Left Typography & CTAs
          Expanded(
            flex: 5,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'The Last\nOriginal.',
                  style: TextStyle(
                    fontSize: 84,
                    height: 1.1,
                    fontWeight: FontWeight.w900,
                    color: kTextColor,
                    letterSpacing: -2,
                  ),
                ),
                const SizedBox(height: 32),
                const Text(
                  'Hardware-level cryptographic sealing and serverless peer-to-peer asset transfer. Built entirely on a zero-trust, air-gapped ledger.',
                  style: TextStyle(
                    fontSize: 18,
                    height: 1.5,
                    color: Colors.black54,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 48),
                Row(
                  children: [
                    SizedBox(
                      width: 240,
                      child: NeomorphicButton(
                        isExpanded: true,
                        onTap: () => _launchApp(context),
                        child: const Text(
                          'INITIALIZE ENCLAVE',
                          style: TextStyle(color: kAccentColor, fontWeight: FontWeight.w900, letterSpacing: 1.5),
                        ),
                      ),
                    ),
                    const SizedBox(width: 32),
                    const Row(
                      children: [
                        Icon(Icons.book_outlined, color: Colors.black45),
                        SizedBox(width: 12),
                        Text('READ THE DOCS', style: TextStyle(color: Colors.black54, fontWeight: FontWeight.bold, letterSpacing: 1)),
                      ],
                    )
                  ],
                )
              ],
            ),
          ),
          
          // Right Abstract Visual (Neomorphic 3D Mockup)
          Expanded(
            flex: 5,
            child: SizedBox(
              height: 500,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  Positioned(
                    right: 40,
                    top: 40,
                    child: NeomorphicContainer(
                      width: 300,
                      height: 300,
                      borderRadius: 150,
                      depressed: true,
                      child: Container(),
                    ),
                  ),
                  Positioned(
                    left: 20,
                    bottom: 20,
                    child: NeomorphicContainer(
                      width: 200,
                      height: 200,
                      borderRadius: 24,
                      child: const Center(
                        child: Icon(Icons.shield_outlined, size: 80, color: kAccentColor),
                      ),
                    ),
                  ),
                  Positioned(
                    right: 120,
                    bottom: 100,
                    child: NeomorphicContainer(
                      width: 140,
                      height: 140,
                      borderRadius: 70,
                      child: const Center(
                        child: Icon(Icons.lock_outline, size: 40, color: kTextColor),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          )
        ],
      ),
    );
  }
}

class _FeatureGrid extends StatelessWidget {
  const _FeatureGrid();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 64),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: const [
          _FeatureCard(
            icon: Icons.offline_bolt_outlined,
            title: 'AIR-GAPPED LEDGER',
            description: 'AES-256 encrypted local storage with strict zero-trust parameters. No cloud synchronization.',
          ),
          SizedBox(width: 32),
          _FeatureCard(
            icon: Icons.memory,
            title: 'C2PA HARDWARE SEAL',
            description: 'Native Rust FFI bridge securely injects JUMBF cryptographic manifests directly into asset bytes.',
          ),
          SizedBox(width: 32),
          _FeatureCard(
            icon: Icons.sensors_outlined,
            title: 'P2P DTLS TUNNEL',
            description: 'Serverless WebRTC file streaming utilizing silent integrity protocols to drop tampered payloads.',
          ),
        ],
      ),
    );
  }
}

class _FeatureCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String description;

  const _FeatureCard({required this.icon, required this.title, required this.description});

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: NeomorphicContainer(
        padding: const EdgeInsets.all(28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            NeomorphicContainer(
              width: 56,
              height: 56,
              borderRadius: 16,
              depressed: true,
              padding: EdgeInsets.zero,
              child: Center(child: Icon(icon, color: kAccentColor, size: 28)),
            ),
            const SizedBox(height: 24),
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16, color: kTextColor, letterSpacing: 1.5)),
            const SizedBox(height: 16),
            Text(description, style: const TextStyle(color: Colors.black54, height: 1.5)),
          ],
        ),
      ),
    );
  }
}

void _launchApp(BuildContext context) {
  Navigator.pushReplacement(
    context,
    PageRouteBuilder(
      pageBuilder: (context, animation, secondaryAnimation) => const DashboardScreen(),
      transitionsBuilder: (context, animation, secondaryAnimation, child) {
        return FadeTransition(opacity: animation, child: child);
      },
      transitionDuration: const Duration(milliseconds: 1200),
    ),
  );
}
