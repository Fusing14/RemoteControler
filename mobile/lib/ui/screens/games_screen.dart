import 'dart:async';
import 'package:flutter/material.dart';

import '../../transport/control_client.dart';

/// Pantalla para listar y lanzar de forma remota juegos detectados en Steam y Epic Games.
class GamesScreen extends StatefulWidget {
  final RemoteControlClient controlClient;

  const GamesScreen({
    super.key,
    required this.controlClient,
  });

  @override
  State<GamesScreen> createState() => _GamesScreenState();
}

class _GamesScreenState extends State<GamesScreen> {
  List<Map<String, dynamic>> _games = [];
  bool _isLoading = true;
  String? _errorMessage;
  String _searchQuery = '';
  String _platformFilter = 'ALL'; // 'ALL', 'STEAM', 'EPIC'
  String? _launchingGameId;

  @override
  void initState() {
    super.initState();
    _loadGames();
  }

  Future<void> _loadGames() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'GAMES_LIST',
        payload: {},
      );

      final status = res['status'] as String?;
      if (status == 'SUCCESS') {
        final data = res['data'] as Map<String, dynamic>?;
        final list = (data?['games'] as List<dynamic>? ?? [])
            .map((e) => e as Map<String, dynamic>)
            .toList();

        if (mounted) {
          setState(() {
            _games = list;
            _isLoading = false;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _errorMessage = res['message'] as String? ?? 'No se pudieron listar los juegos.';
            _isLoading = false;
          });
        }
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString().replaceAll('Exception: ', '');
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _launchGame(Map<String, dynamic> game) async {
    final gameId = game['game_id'] as String;
    final platform = (game['platform'] as String?)?.toLowerCase() ?? 'steam';
    final gameName = game['name'] as String? ?? 'Juego';
    final cardId = game['id'] as String? ?? gameId;

    setState(() => _launchingGameId = cardId);

    try {
      final res = await widget.controlClient.sendCommand(
        commandId: 'GAME_LAUNCH',
        payload: {
          'platform': platform,
          'game_id': gameId,
        },
      );

      final status = res['status'] as String?;
      if (mounted) {
        if (status == 'SUCCESS') {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              backgroundColor: const Color(0xFF10B981),
              content: Text(
                'Lanzando $gameName en el PC...',
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
              ),
              duration: const Duration(seconds: 2),
            ),
          );
        } else {
          throw Exception(res['message'] ?? 'Fallo al lanzar el juego en el PC.');
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFFEF4444),
            content: Text(
              'Error al lanzar: ${e.toString().replaceAll('Exception: ', '')}',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600),
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _launchingGameId = null);
      }
    }
  }

  List<Map<String, dynamic>> get _filteredGames {
    return _games.where((game) {
      final name = (game['name'] as String? ?? '').toLowerCase();
      final plat = (game['platform'] as String? ?? '').toUpperCase();

      final matchesQuery = _searchQuery.isEmpty || name.contains(_searchQuery.toLowerCase());
      final matchesPlatform = _platformFilter == 'ALL' || plat == _platformFilter;

      return matchesQuery && matchesPlatform;
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final filtered = _filteredGames;

    return Scaffold(
      backgroundColor: const Color(0xFF090A0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF11141C),
        elevation: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Juegos Instalados',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold, color: Colors.white),
            ),
            if (!_isLoading)
              Text(
                '${filtered.length} de ${_games.length} títulos',
                style: const TextStyle(fontSize: 11, color: Color(0xFF94A3B8)),
              ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: Colors.white70),
            tooltip: 'Actualizar biblioteca',
            onPressed: _loadGames,
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            // Barra de Búsqueda y Filtros
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              color: const Color(0xFF0F1117),
              child: Column(
                children: [
                  TextField(
                    onChanged: (val) => setState(() => _searchQuery = val.trim()),
                    style: const TextStyle(color: Colors.white, fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'Buscar juego por título...',
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
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      _buildFilterChip('Todos', 'ALL'),
                      const SizedBox(width: 8),
                      _buildFilterChip('Steam', 'STEAM'),
                      const SizedBox(width: 8),
                      _buildFilterChip('Epic Games', 'EPIC'),
                    ],
                  ),
                ],
              ),
            ),

            // Contenido Principal
            Expanded(
              child: _isLoading
                  ? const Center(
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          CircularProgressIndicator(color: Color(0xFF10B981)),
                          SizedBox(height: 16),
                          Text('Escaneando discos del PC...', style: TextStyle(color: Colors.white70)),
                        ],
                      ),
                    )
                  : _errorMessage != null
                      ? Center(
                          child: Padding(
                            padding: const EdgeInsets.all(24),
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(Icons.error_outline, size: 48, color: Color(0xFFEF4444)),
                                const SizedBox(height: 12),
                                Text(
                                  _errorMessage!,
                                  textAlign: TextAlign.center,
                                  style: const TextStyle(color: Colors.white),
                                ),
                                const SizedBox(height: 16),
                                ElevatedButton.icon(
                                  style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFF10B981)),
                                  icon: const Icon(Icons.refresh, color: Colors.white),
                                  label: const Text('Reintentar', style: TextStyle(color: Colors.white)),
                                  onPressed: _loadGames,
                                ),
                              ],
                            ),
                          ),
                        )
                      : filtered.isEmpty
                          ? const Center(
                              child: Text(
                                'No se encontraron juegos con ese filtro.',
                                style: TextStyle(color: Colors.white54, fontSize: 14),
                              ),
                            )
                          : ListView.separated(
                              padding: const EdgeInsets.all(16),
                              itemCount: filtered.length,
                              separatorBuilder: (_, __) => const SizedBox(height: 10),
                              itemBuilder: (ctx, index) {
                                final game = filtered[index];
                                final isSteam = (game['platform'] as String?)?.toLowerCase() == 'steam';
                                final cardId = game['id'] as String? ?? game['game_id'];
                                final isLaunching = _launchingGameId == cardId;

                                return Container(
                                  padding: const EdgeInsets.all(12),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF161A23),
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(color: const Color(0xFF1E2230)),
                                  ),
                                  child: Row(
                                    children: [
                                      Container(
                                        width: 44,
                                        height: 44,
                                        decoration: BoxDecoration(
                                          color: isSteam ? const Color(0xFF171A21) : const Color(0xFF2B2B2B),
                                          borderRadius: BorderRadius.circular(10),
                                        ),
                                        child: Icon(
                                          isSteam ? Icons.sports_esports_rounded : Icons.flash_on_rounded,
                                          color: isSteam ? const Color(0xFF66C0F4) : const Color(0xFF0078F2),
                                          size: 24,
                                        ),
                                      ),
                                      const SizedBox(width: 12),
                                      Expanded(
                                        child: Column(
                                          crossAxisAlignment: CrossAxisAlignment.start,
                                          children: [
                                            Text(
                                              game['name'] ?? 'Desconocido',
                                              maxLines: 1,
                                              overflow: TextOverflow.ellipsis,
                                              style: const TextStyle(
                                                color: Colors.white,
                                                fontWeight: FontWeight.bold,
                                                fontSize: 14,
                                              ),
                                            ),
                                            const SizedBox(height: 4),
                                            Row(
                                              children: [
                                                Container(
                                                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                                  decoration: BoxDecoration(
                                                    color: isSteam
                                                        ? const Color(0xFF66C0F4).withOpacity(0.15)
                                                        : const Color(0xFF0078F2).withOpacity(0.15),
                                                    borderRadius: BorderRadius.circular(4),
                                                  ),
                                                  child: Text(
                                                    isSteam ? 'STEAM' : 'EPIC GAMES',
                                                    style: TextStyle(
                                                      color: isSteam ? const Color(0xFF66C0F4) : const Color(0xFF3B82F6),
                                                      fontSize: 10,
                                                      fontWeight: FontWeight.w700,
                                                    ),
                                                  ),
                                                ),
                                                const SizedBox(width: 8),
                                                Text(
                                                  'ID: ${game['game_id']}',
                                                  style: const TextStyle(color: Colors.white38, fontSize: 11),
                                                ),
                                              ],
                                            ),
                                          ],
                                        ),
                                      ),
                                      const SizedBox(width: 10),
                                      ElevatedButton(
                                        style: ElevatedButton.styleFrom(
                                          backgroundColor: const Color(0xFF10B981),
                                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                                        ),
                                        onPressed: isLaunching ? null : () => _launchGame(game),
                                        child: isLaunching
                                            ? const SizedBox(
                                                width: 16,
                                                height: 16,
                                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                                              )
                                            : const Row(
                                                mainAxisSize: MainAxisSize.min,
                                                children: [
                                                  Icon(Icons.play_arrow, size: 16, color: Colors.white),
                                                  SizedBox(width: 4),
                                                  Text(
                                                    'Jugar',
                                                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12),
                                                  ),
                                                ],
                                              ),
                                      ),
                                    ],
                                  ),
                                );
                              },
                            ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilterChip(String label, String value) {
    final isSelected = _platformFilter == value;
    return GestureDetector(
      onTap: () => setState(() => _platformFilter = value),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected ? const Color(0xFF6366F1) : const Color(0xFF161A23),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected ? const Color(0xFF6366F1) : const Color(0xFF1E2230),
          ),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: isSelected ? Colors.white : Colors.white60,
            fontSize: 12,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
          ),
        ),
      ),
    );
  }
}
