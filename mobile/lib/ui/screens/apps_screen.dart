import 'dart:async';
import 'package:flutter/material.dart';

import '../../transport/control_client.dart';

/// Pantalla para listar y gestionar aplicaciones en el PC:
/// Pestaña 1: Instaladas (Buscar y abrir aplicaciones).
/// Pestaña 2: Abiertas (Task Manager para ver ventanas activas y cerrar/forzar cierre).
class AppsScreen extends StatefulWidget {
  final RemoteControlClient controlClient;

  const AppsScreen({
    super.key,
    required this.controlClient,
  });

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  // Estado Pestaña 1: Instaladas
  List<Map<String, dynamic>> _apps = [];
  bool _isLoadingApps = true;
  String? _appsErrorMessage;
  String _searchQuery = '';
  String? _launchingAppId;

  // Estado Pestaña 2: Abiertas en ejecución
  List<Map<String, dynamic>> _runningApps = [];
  bool _isLoadingRunning = false;
  String? _runningErrorMessage;
  String _runningSearchQuery = '';
  int? _closingPid;

  @override
  void initState() {
    super.initState();
    _loadInstalledApps();
    _loadRunningApps();
  }

  Future<void> _loadInstalledApps() async {
    setState(() {
      _isLoadingApps = true;
      _appsErrorMessage = null;
    });

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'APPS_LIST',
        payload: {},
      );

      final status = res['status'] as String?;
      if (status == 'SUCCESS') {
        final data = res['data'] as Map<String, dynamic>?;
        final list = (data?['apps'] as List<dynamic>? ?? [])
            .map((e) => e as Map<String, dynamic>)
            .toList();

        if (mounted) {
          setState(() {
            _apps = list;
            _isLoadingApps = false;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _appsErrorMessage = res['message'] as String? ?? 'No se pudieron listar las aplicaciones.';
            _isLoadingApps = false;
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _appsErrorMessage = e.toString().replaceAll('Exception: ', '');
          _isLoadingApps = false;
        });
      }
    }
  }

  Future<void> _loadRunningApps() async {
    setState(() {
      _isLoadingRunning = true;
      _runningErrorMessage = null;
    });

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'RUNNING_APPS_LIST',
        payload: {},
      );

      final status = res['status'] as String?;
      if (status == 'SUCCESS') {
        final data = res['data'] as Map<String, dynamic>?;
        final list = (data?['apps'] as List<dynamic>? ?? [])
            .map((e) => e as Map<String, dynamic>)
            .toList();

        if (mounted) {
          setState(() {
            _runningApps = list;
            _isLoadingRunning = false;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _runningErrorMessage = res['message'] as String? ?? 'No se pudieron listar los procesos activos.';
            _isLoadingRunning = false;
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _runningErrorMessage = e.toString().replaceAll('Exception: ', '');
          _isLoadingRunning = false;
        });
      }
    }
  }

  Future<void> _launchApp(Map<String, dynamic> app) async {
    final appId = app['app_id'] as String? ?? '';
    final appName = app['name'] as String? ?? 'Aplicación';
    final targetPath = app['target_path'] as String? ?? '';

    setState(() => _launchingAppId = appId);

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'APP_LAUNCH',
        payload: {
          'platform': 'SYSTEM',
          'app_id': appId,
          'target_path': targetPath,
        },
      );

      final status = res['status'] as String?;
      if (mounted) {
        if (status == 'SUCCESS') {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              backgroundColor: const Color(0xFF10B981),
              content: Text(
                'Abriendo $appName en el PC...',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
              ),
              duration: const Duration(seconds: 2),
            ),
          );
        } else {
          throw Exception(res['message'] ?? 'Fallo al iniciar la aplicación en el PC.');
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              'Error al abrir: ${e.toString().replaceAll('Exception: ', '')}',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _launchingAppId = null);
      }
    }
  }

  Future<void> _closeRunningApp(int pid, String appName, {required bool force}) async {
    if (force) {
      final confirm = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: const Color(0xFF161A23),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          title: const Row(
            children: [
              Icon(Icons.warning_amber_rounded, color: Color(0xFFEF4444), size: 26),
              SizedBox(width: 10),
              Text('Forzar Cierre', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 18)),
            ],
          ),
          content: Text(
            '¿Deseas forzar la finalización de "$appName" (PID $pid)? Los datos no guardados podrían perderse.',
            style: const TextStyle(color: Color(0xFFCBD5E1), fontSize: 13),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancelar', style: TextStyle(color: Colors.white54)),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFEF4444)),
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Forzar', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
            ),
          ],
        ),
      );
      if (confirm != true) return;
    }

    setState(() => _closingPid = pid);

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'APP_CLOSE',
        payload: {
          'pid': pid,
          'force': force,
        },
      );

      final status = res['status'] as String?;
      if (mounted) {
        if (status == 'SUCCESS') {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              backgroundColor: const Color(0xFF10B981),
              content: Text(
                force ? 'Proceso $appName terminado a la fuerza.' : 'Cerrando $appName...',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
              ),
              duration: const Duration(seconds: 2),
            ),
          );
          await _loadRunningApps();
        } else {
          throw Exception(res['message'] ?? 'No se pudo cerrar la aplicación.');
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              'Error al cerrar: ${e.toString().replaceAll('Exception: ', '')}',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _closingPid = null);
      }
    }
  }

  List<Map<String, dynamic>> get _filteredInstalledApps {
    if (_searchQuery.isEmpty) return _apps;
    final q = _searchQuery.toLowerCase();
    return _apps.where((app) {
      final name = (app['name'] as String? ?? '').toLowerCase();
      return name.contains(q);
    }).toList();
  }

  List<Map<String, dynamic>> get _filteredRunningApps {
    if (_runningSearchQuery.isEmpty) return _runningApps;
    final q = _runningSearchQuery.toLowerCase();
    return _runningApps.where((app) {
      final name = (app['name'] as String? ?? '').toLowerCase();
      final title = (app['title'] as String? ?? '').toLowerCase();
      return name.contains(q) || title.contains(q);
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 2,
      child: Scaffold(
        backgroundColor: const Color(0xFF090A0F),
        appBar: AppBar(
          backgroundColor: const Color(0xFF11141C),
          elevation: 0,
          title: const Text(
            'Gestor de Aplicaciones',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
          ),
          bottom: const TabBar(
            indicatorColor: Color(0xFF6366F1),
            indicatorWeight: 3,
            labelColor: Colors.white,
            unselectedLabelColor: Color(0xFF94A3B8),
            labelStyle: TextStyle(fontWeight: FontWeight.bold, fontSize: 13),
            tabs: [
              Tab(
                icon: Icon(Icons.apps_rounded, size: 20),
                text: 'Instaladas (Abrir)',
              ),
              Tab(
                icon: Icon(Icons.view_carousel_rounded, size: 20),
                text: 'Abiertas (Cerrar)',
              ),
            ],
          ),
          actions: [
            IconButton(
              icon: const Icon(Icons.refresh, color: Colors.white70),
              tooltip: 'Actualizar',
              onPressed: () {
                _loadInstalledApps();
                _loadRunningApps();
              },
            ),
          ],
        ),
        body: TabBarView(
          children: [
            _buildInstalledTab(),
            _buildRunningTab(),
          ],
        ),
      ),
    );
  }

  Widget _buildInstalledTab() {
    final filtered = _filteredInstalledApps;

    return Column(
      children: [
        // Campo de búsqueda en vivo
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          color: const Color(0xFF0F1117),
          child: TextField(
            onChanged: (val) => setState(() => _searchQuery = val.trim()),
            style: const TextStyle(color: Colors.white, fontSize: 14),
            decoration: InputDecoration(
              hintText: 'Buscar aplicación instalada...',
              hintStyle: const TextStyle(color: Colors.white38, fontSize: 14),
              prefixIcon: const Icon(Icons.search, color: Colors.white54, size: 20),
              filled: true,
              fillColor: const Color(0xFF161A23),
              contentPadding: const EdgeInsets.symmetric(vertical: 0, horizontal: 16),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: BorderSide.none,
              ),
            ),
          ),
        ),

        // Contenido principal
        Expanded(
          child: _isLoadingApps
              ? const Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      CircularProgressIndicator(color: Color(0xFF6366F1)),
                      SizedBox(height: 16),
                      Text('Explorando programas en el PC...', style: TextStyle(color: Colors.white70)),
                    ],
                  ),
                )
              : _appsErrorMessage != null
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.error_outline, size: 48, color: Color(0xFFEF4444)),
                            const SizedBox(height: 12),
                            Text(_appsErrorMessage!, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white)),
                            const SizedBox(height: 16),
                            ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF6366F1)),
                              icon: const Icon(Icons.refresh, color: Colors.white),
                              label: const Text('Reintentar', style: TextStyle(color: Colors.white)),
                              onPressed: _loadInstalledApps,
                            ),
                          ],
                        ),
                      ),
                    )
                  : filtered.isEmpty
                      ? const Center(
                          child: Text(
                            'No se encontraron aplicaciones.',
                            style: TextStyle(color: Colors.white54, fontSize: 14),
                          ),
                        )
                      : ListView.separated(
                          padding: const EdgeInsets.all(16),
                          itemCount: filtered.length,
                          separatorBuilder: (_, __) => const SizedBox(height: 10),
                          itemBuilder: (ctx, index) {
                            final app = filtered[index];
                            final appId = app['app_id'] as String? ?? '';
                            final isLaunching = _launchingAppId == appId;

                            return Container(
                              decoration: BoxDecoration(
                                color: const Color(0xFF161A23),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFF1E2230)),
                              ),
                              child: ListTile(
                                leading: Container(
                                  width: 44,
                                  height: 44,
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF6366F1).withOpacity(0.12),
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                  child: const Icon(Icons.launch_rounded, color: Color(0xFF6366F1), size: 22),
                                ),
                                title: Text(
                                  app['name'] as String? ?? 'Aplicación',
                                  style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14),
                                ),
                                subtitle: Text(
                                  app['target_path'] as String? ?? 'Acceso directo de Windows',
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                                ),
                                trailing: ElevatedButton(
                                  style: ElevatedButton.styleFrom(
                                    backgroundColor: const Color(0xFF6366F1),
                                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                                  ),
                                  onPressed: isLaunching ? null : () => _launchApp(app),
                                  child: isLaunching
                                      ? const SizedBox(
                                          width: 16,
                                          height: 16,
                                          child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                                        )
                                      : const Text(
                                          'Abrir',
                                          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                                        ),
                                ),
                              ),
                            );
                          },
                        ),
        ),
      ],
    );
  }

  Widget _buildRunningTab() {
    final filtered = _filteredRunningApps;

    return Column(
      children: [
        // Campo de búsqueda en vivo para aplicaciones abiertas
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          color: const Color(0xFF0F1117),
          child: TextField(
            onChanged: (val) => setState(() => _runningSearchQuery = val.trim()),
            style: const TextStyle(color: Colors.white, fontSize: 14),
            decoration: InputDecoration(
              hintText: 'Buscar en apps activas o ventanas...',
              hintStyle: const TextStyle(color: Colors.white38, fontSize: 14),
              prefixIcon: const Icon(Icons.search, color: Colors.white54, size: 20),
              filled: true,
              fillColor: const Color(0xFF161A23),
              contentPadding: const EdgeInsets.symmetric(vertical: 0, horizontal: 16),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10),
                borderSide: BorderSide.none,
              ),
            ),
          ),
        ),

        // Contenido principal
        Expanded(
          child: _isLoadingRunning
              ? const Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      CircularProgressIndicator(color: Color(0xFF10B981)),
                      SizedBox(height: 16),
                      Text('Consultando ventanas y tareas en el PC...', style: TextStyle(color: Colors.white70)),
                    ],
                  ),
                )
              : _runningErrorMessage != null
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.error_outline, size: 48, color: Color(0xFFEF4444)),
                            const SizedBox(height: 12),
                            Text(_runningErrorMessage!, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white)),
                            const SizedBox(height: 16),
                            ElevatedButton.icon(
                              style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF10B981)),
                              icon: const Icon(Icons.refresh, color: Colors.white),
                              label: const Text('Reintentar', style: TextStyle(color: Colors.white)),
                              onPressed: _loadRunningApps,
                            ),
                          ],
                        ),
                      ),
                    )
                  : filtered.isEmpty
                      ? const Center(
                          child: Text(
                            'No hay aplicaciones activas en el escritorio.',
                            style: TextStyle(color: Colors.white54, fontSize: 14),
                          ),
                        )
                      : ListView.separated(
                          padding: const EdgeInsets.all(16),
                          itemCount: filtered.length,
                          separatorBuilder: (_, __) => const SizedBox(height: 10),
                          itemBuilder: (ctx, index) {
                            final app = filtered[index];
                            final pid = app['pid'] as int? ?? 0;
                            final name = app['name'] as String? ?? 'Proceso';
                            final title = app['title'] as String? ?? name;
                            final isClosing = _closingPid == pid;

                            return Container(
                              decoration: BoxDecoration(
                                color: const Color(0xFF161A23),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFF1E2230)),
                              ),
                              child: Padding(
                                padding: const EdgeInsets.all(12),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      children: [
                                        Container(
                                          width: 38,
                                          height: 38,
                                          decoration: BoxDecoration(
                                            color: const Color(0xFF10B981).withOpacity(0.12),
                                            borderRadius: BorderRadius.circular(8),
                                          ),
                                          child: const Icon(Icons.desktop_windows_rounded, color: Color(0xFF10B981), size: 20),
                                        ),
                                        const SizedBox(width: 12),
                                        Expanded(
                                          child: Column(
                                            crossAxisAlignment: CrossAxisAlignment.start,
                                            children: [
                                              Text(
                                                title,
                                                maxLines: 1,
                                                overflow: TextOverflow.ellipsis,
                                                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14),
                                              ),
                                              const SizedBox(height: 2),
                                              Text(
                                                '$name • PID $pid',
                                                style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11, fontWeight: FontWeight.w500),
                                              ),
                                            ],
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 12),
                                    Row(
                                      mainAxisAlignment: MainAxisAlignment.end,
                                      children: [
                                        OutlinedButton.icon(
                                          style: OutlinedButton.styleFrom(
                                            foregroundColor: const Color(0xFFF59E0B),
                                            side: const BorderSide(color: Color(0xFFF59E0B), width: 1),
                                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                                          ),
                                          icon: isClosing
                                              ? const SizedBox(
                                                  width: 14,
                                                  height: 14,
                                                  child: CircularProgressIndicator(strokeWidth: 2, color: Color(0xFFF59E0B)),
                                                )
                                              : const Icon(Icons.close_rounded, size: 16),
                                          label: const Text('Cerrar', style: TextStyle(fontSize: 12)),
                                          onPressed: isClosing ? null : () => _closeRunningApp(pid, name, force: false),
                                        ),
                                        const SizedBox(width: 8),
                                        ElevatedButton.icon(
                                          style: ElevatedButton.styleFrom(
                                            backgroundColor: const Color(0xFFEF4444),
                                            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                                            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                                          ),
                                          icon: const Icon(Icons.dangerous_rounded, size: 16, color: Colors.white),
                                          label: const Text('Forzar', style: TextStyle(fontSize: 12, color: Colors.white, fontWeight: FontWeight.bold)),
                                          onPressed: isClosing ? null : () => _closeRunningApp(pid, name, force: true),
                                        ),
                                      ],
                                    ),
                                  ],
                                ),
                              ),
                            );
                          },
                        ),
        ),
      ],
    );
  }
}
