import 'dart:async';
import 'package:flutter/material.dart';

import '../../crypto/key_manager.dart';
import '../../services/pairing_client.dart';
import '../../services/saved_hosts_service.dart';
import '../../services/wol_service.dart';
import 'scanner_screen.dart';

/// Pantalla de gestión multi-PC ("Mis Ordenadores").
/// Permite ver todos los ordenadores guardados, comprobar si están encendidos en tiempo real (ping),
/// encenderlos mediante Wake-on-LAN, cambiar el ordenador activo, renombrarlos o vincular nuevos PCs.
class HostsManagerScreen extends StatefulWidget {
  final SavedHostsService savedHostsService;
  final PairingClient pairingClient;
  final KeyManager keyManager;
  final String? currentActiveEndpoint;

  const HostsManagerScreen({
    super.key,
    required this.savedHostsService,
    required this.pairingClient,
    required this.keyManager,
    this.currentActiveEndpoint,
  });

  @override
  State<HostsManagerScreen> createState() => _HostsManagerScreenState();
}

class _HostsManagerScreenState extends State<HostsManagerScreen> {
  List<SavedHost> _hosts = [];
  String? _activeHostId;
  final Map<String, bool?> _pingStatus =
      {}; // true = online, false = offline, null = pinging
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadHosts();
  }

  Future<void> _loadHosts() async {
    setState(() {
      _isLoading = true;
    });

    final hosts = await widget.savedHostsService.getHosts();
    final activeId = await widget.savedHostsService.getActiveHostId();

    if (mounted) {
      setState(() {
        _hosts = hosts;
        _activeHostId = activeId ?? (hosts.isNotEmpty ? hosts.first.id : null);
        _isLoading = false;
      });
      _pingAllHosts(hosts);
    }
  }

  void _pingAllHosts(List<SavedHost> hosts) {
    for (final host in hosts) {
      _pingStatus[host.id] = null; // pinging
      widget.savedHostsService.pingHost(host.endpoint).then((isOnline) {
        if (mounted) {
          setState(() {
            _pingStatus[host.id] = isOnline;
          });
        }
      });
    }
  }

  Future<void> _selectHost(SavedHost host) async {
    await widget.savedHostsService.setActiveHostId(host.id);
    if (mounted) {
      Navigator.of(context).pop(host);
    }
  }

  Future<void> _wakeHost(SavedHost host) async {
    final mac = host.macAddress;
    if (mac == null || mac.trim().isEmpty) {
      _showMacInputDialog(host);
      return;
    }

    try {
      await WolService.wake(
        macAddress: mac,
        broadcastIp: host.broadcastIp,
        hostIpOrEndpoint: host.endpoint,
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF10B981),
            content: Row(
              children: [
                const Icon(Icons.bolt_rounded, color: Colors.white, size: 20),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Paquete Mágico WoL transmitido a "${host.customName}" ($mac)',
                    style: const TextStyle(
                        color: Colors.white, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text('Error Wake-on-LAN: $e'),
          ),
        );
      }
    }
  }

  Future<void> _showMacInputDialog(SavedHost host) async {
    final ctrl = TextEditingController();
    final entered = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161A23),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Configurar MAC para Encendido',
            style: TextStyle(color: Colors.white)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Este ordenador no tiene una MAC registrada. Introduce la MAC física para encenderlo vía Wake-on-LAN:',
              style: TextStyle(color: Color(0xFF94A3B8), fontSize: 13),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              style:
                  const TextStyle(color: Colors.white, fontFamily: 'Consolas'),
              decoration: InputDecoration(
                hintText: 'XX:XX:XX:XX:XX:XX',
                hintStyle: const TextStyle(color: Colors.white38),
                filled: true,
                fillColor: const Color(0xFF0F1117),
                border:
                    OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancelar')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF10B981)),
            onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
            child: const Text('Guardar y Encender',
                style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (entered != null && entered.trim().isNotEmpty) {
      await widget.savedHostsService.addOrUpdateHost(
        endpoint: host.endpoint,
        deviceId: host.deviceId,
        customName: host.customName,
        macAddress: entered.trim(),
        broadcastIp: host.broadcastIp,
      );
      await _loadHosts();
      final updated = _hosts.where((h) => h.id == host.id).firstOrNull;
      if (updated != null) {
        _wakeHost(updated);
      }
    }
  }

  Future<void> _renameHost(SavedHost host) async {
    final ctrl = TextEditingController(text: host.customName);
    final newName = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161A23),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Renombrar Ordenador',
            style: TextStyle(color: Colors.white)),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Ej: PC Despacho, Gaming Rig...',
            hintStyle: const TextStyle(color: Colors.white38),
            filled: true,
            fillColor: const Color(0xFF0F1117),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancelar')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF6366F1)),
            onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
            child: const Text('Guardar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (newName != null && newName.isNotEmpty && newName != host.customName) {
      await widget.savedHostsService.renameHost(host.id, newName);
      await _loadHosts();
    }
  }

  Future<void> _deleteHost(SavedHost host) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF161A23),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Eliminar Ordenador',
            style: TextStyle(color: Colors.white)),
        content: Text(
          '¿Estás seguro de que deseas eliminar "${host.customName}"?\nDeberás volver a escanear el código QR para vincularlo nuevamente.',
          style: const TextStyle(color: Color(0xFF94A3B8)),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancelar')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFEF4444)),
            onPressed: () => Navigator.pop(ctx, true),
            child:
                const Text('Eliminar', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );

    if (confirm == true) {
      await widget.savedHostsService.removeHost(host.id);
      await _loadHosts();
    }
  }

  Future<void> _pairNewHost() async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ScannerScreen(
          pairingClient: widget.pairingClient,
          keyManager: widget.keyManager,
        ),
      ),
    );
    await _loadHosts();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF090A0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF11141C),
        elevation: 0,
        title: const Row(
          children: [
            Icon(Icons.devices_rounded, color: Color(0xFF6366F1), size: 22),
            SizedBox(width: 10),
            Text('Mis Ordenadores',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: Colors.white70),
            tooltip: 'Comprobar estado de conexión',
            onPressed: () => _pingAllHosts(_hosts),
          ),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(color: Color(0xFF6366F1)))
          : _hosts.isEmpty
              ? _buildEmptyState()
              : _buildHostsList(),
      bottomNavigationBar: Container(
        padding: const EdgeInsets.all(16),
        decoration: const BoxDecoration(
          color: Color(0xFF11141C),
          border: Border(top: BorderSide(color: Color(0xFF1E2230))),
        ),
        child: ElevatedButton.icon(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF6366F1),
            padding: const EdgeInsets.symmetric(vertical: 14),
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          ),
          icon: const Icon(Icons.qr_code_scanner_rounded, color: Colors.white),
          label: const Text(
            '+ Vincular Nuevo Ordenador',
            style: TextStyle(
                color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold),
          ),
          onPressed: _pairNewHost,
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.computer_rounded, size: 64, color: Colors.white24),
          const SizedBox(height: 16),
          const Text(
            'No tienes ordenadores vinculados',
            style: TextStyle(
                color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          const Text(
            'Escanea el código QR desde el panel del PC para comenzar.',
            style: TextStyle(color: Color(0xFF94A3B8), fontSize: 14),
          ),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF6366F1)),
            icon:
                const Icon(Icons.qr_code_scanner_rounded, color: Colors.white),
            label: const Text('Escanear QR',
                style: TextStyle(color: Colors.white)),
            onPressed: _pairNewHost,
          ),
        ],
      ),
    );
  }

  Widget _buildHostsList() {
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _hosts.length,
      itemBuilder: (context, index) {
        final host = _hosts[index];
        final isActive = host.id == _activeHostId ||
            host.endpoint == widget.currentActiveEndpoint;
        final ping = _pingStatus[host.id];

        return Container(
          margin: const EdgeInsets.only(bottom: 14),
          decoration: BoxDecoration(
            color: const Color(0xFF11141C),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color:
                  isActive ? const Color(0xFF6366F1) : const Color(0xFF1E2230),
              width: isActive ? 2 : 1,
            ),
          ),
          child: InkWell(
            borderRadius: BorderRadius.circular(16),
            onTap: () => _selectHost(host),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Encabezado de la tarjeta
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: isActive
                              ? const Color(0xFF6366F1).withOpacity(0.15)
                              : const Color(0xFF1E2230),
                          borderRadius: BorderRadius.circular(10),
                        ),
                        child: Icon(
                          Icons.laptop_chromebook_rounded,
                          color: isActive
                              ? const Color(0xFF6366F1)
                              : const Color(0xFF94A3B8),
                          size: 24,
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              host.customName,
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              host.endpoint,
                              style: const TextStyle(
                                color: Color(0xFF94A3B8),
                                fontSize: 13,
                                fontFamily: 'Consolas',
                              ),
                            ),
                          ],
                        ),
                      ),
                      if (isActive)
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: const Color(0xFF6366F1).withOpacity(0.2),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: const Color(0xFF6366F1)),
                          ),
                          child: const Text(
                            'ACTIVO',
                            style: TextStyle(
                              color: Color(0xFF6366F1),
                              fontSize: 11,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  const Divider(color: Color(0xFF1E2230), height: 1),
                  const SizedBox(height: 10),

                  // Estado de red (Ping / Online / Offline)
                  Row(
                    children: [
                      _buildOnlineBadge(ping),
                      const Spacer(),
                      // Botones de acción rápida
                      IconButton(
                        icon: const Icon(Icons.bolt_rounded,
                            color: Color(0xFF10B981), size: 22),
                        tooltip: 'Encender mediante Wake-on-LAN',
                        onPressed: () => _wakeHost(host),
                      ),
                      IconButton(
                        icon: const Icon(Icons.edit_rounded,
                            color: Color(0xFF94A3B8), size: 20),
                        tooltip: 'Renombrar',
                        onPressed: () => _renameHost(host),
                      ),
                      IconButton(
                        icon: const Icon(Icons.delete_outline_rounded,
                            color: Color(0xFFEF4444), size: 20),
                        tooltip: 'Eliminar ordenador',
                        onPressed: () => _deleteHost(host),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildOnlineBadge(bool? isOnline) {
    if (isOnline == null) {
      return const Row(
        children: [
          SizedBox(
            width: 10,
            height: 10,
            child: CircularProgressIndicator(
                strokeWidth: 2, color: Color(0xFFF59E0B)),
          ),
          SizedBox(width: 8),
          Text('Comprobando...',
              style: TextStyle(color: Color(0xFF94A3B8), fontSize: 12)),
        ],
      );
    }

    final color = isOnline ? const Color(0xFF10B981) : const Color(0xFF64748B);
    final text = isOnline ? 'En línea' : 'Apagado / Inaccesible';

    return Row(
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 8),
        Text(
          text,
          style: TextStyle(
              color: color, fontSize: 12, fontWeight: FontWeight.w600),
        ),
      ],
    );
  }
}
