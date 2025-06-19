<x-app-layout>
    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8 space-y-10">

            <!-- Reset Button -->
            <div class="flex justify-end mb-4">
                <form method="POST" action="{{ route('history.reset') }}">
                    @csrf
                    <button class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded">
                        Reset History
                    </button>
                </form>
            </div>

            <!-- Chart Section Side-by-Side -->
<div class="bg-white p-6 rounded shadow-sm">
    <h2 class="text-xl font-bold mb-4">Encryption vs Decryption Time (seconds)</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Encryption Chart -->
        <div class="bg-white p-4 rounded shadow">
            <h2 class="text-center font-semibold mb-2">Encryption Duration</h2>
            <canvas id="encryptionChart" height="200"></canvas>
        </div>

        <!-- Decryption Chart -->
        <div class="bg-white p-4 rounded shadow">
            <h2 class="text-center font-semibold mb-2">Decryption Duration</h2>
            <canvas id="decryptionChart" height="200"></canvas>
        </div>
    </div>
</div>


            <!-- Encryption Table -->
            <div class="bg-white p-6 rounded shadow-sm">
                <h2 class="text-xl font-bold mb-4">Encryption Logs</h2>
                <table class="table-auto w-full mb-6">
                    <thead>
                        <tr class="bg-gray-200 text-left">
                            <th class="px-4 py-2">#</th>
                            <th class="px-4 py-2">File</th>
                            <th class="px-4 py-2">Algo</th>
                            <th class="px-4 py-2">Size</th>
                            <th class="px-4 py-2">Time</th>
                            <th class="px-4 py-2">Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($encryptionLogs as $log)
                        <tr class="border-t">
                            <td class="px-4 py-2">{{ $loop->iteration }}</td>
                            <td class="px-4 py-2">{{ $log->file_name }}</td>
                            <td class="px-4 py-2">{{ $log->algorithm }}</td>
                            <td class="px-4 py-2">{{ $log->file_size }}</td>
                            <td class="px-4 py-2">{{ $log->duration }}</td>
                            <td class="px-4 py-2">{{ $log->created_at->format('d M Y H:i') }}</td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="6" class="text-center text-gray-500 py-4">No encryption logs found.</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            <!-- Decryption Table -->
            <div class="bg-white p-6 rounded shadow-sm">
                <h2 class="text-xl font-bold mb-4">Decryption Logs</h2>
                <table class="table-auto w-full mb-6">
                    <thead>
                        <tr class="bg-gray-200 text-left">
                            <th class="px-4 py-2">#</th>
                            <th class="px-4 py-2">File</th>
                            <th class="px-4 py-2">Algo</th>
                            <th class="px-4 py-2">Size</th>
                            <th class="px-4 py-2">Time</th>
                            <th class="px-4 py-2">Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($decryptionLogs as $log)
                        <tr class="border-t">
                            <td class="px-4 py-2">{{ $loop->iteration }}</td>
                            <td class="px-4 py-2">{{ $log->file_name }}</td>
                            <td class="px-4 py-2">{{ $log->algorithm }}</td>
                            <td class="px-4 py-2">{{ $log->file_size }}</td>
                            <td class="px-4 py-2">{{ $log->duration }}</td>
                            <td class="px-4 py-2">{{ $log->created_at->format('d M Y H:i') }}</td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="6" class="text-center text-gray-500 py-4">No decryption logs found.</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

        </div>
    </div>

    <!-- Chart.js Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        const encryptionChartData = {
            labels: {!! json_encode($encryptionLogs->pluck('algorithm')) !!},
            datasets: [{
                label: 'Encryption Duration (s)',
                data: {!! json_encode($encryptionLogs->pluck('duration')) !!},
                backgroundColor: 'rgba(75, 192, 192, 0.7)'
            }]
        };

        const decryptionChartData = {
            labels: {!! json_encode($decryptionLogs->pluck('algorithm')) !!},
            datasets: [{
                label: 'Decryption Duration (s)',
                data: {!! json_encode($decryptionLogs->pluck('duration')) !!},
                backgroundColor: 'rgba(255, 99, 132, 0.7)'
            }]
        };

        new Chart(document.getElementById('encryptionChart'), {
            type: 'bar',
            data: encryptionChartData,
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });

        new Chart(document.getElementById('decryptionChart'), {
            type: 'bar',
            data: decryptionChartData,
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
    </script>
</x-app-layout>
