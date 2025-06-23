<?php
namespace Tests\Feature;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;
use App\Models\User;

class EncryptionTest extends TestCase
{
    public function test_aes_encrypt_decrypt()
    {
        Storage::fake('local');
        $this->actingAs(User::factory()->create());
        $contents = 'Hello AES!';
        $file = UploadedFile::fake()->createWithContent('a.txt', $contents);

        // Encrypt
        $this->post(route('encrypt.aes'), [
            'file' => $file,
            'password' => 'secret',
            'filename' => 'foo'
        ])->assertSessionHas('download_file');
        $enc = session('download_file');

        // Decrypt
        $path = Storage::disk('local')->path("encrypted/{$enc}");
        $encUpload = new UploadedFile($path, $enc, null, null, true);
        $this->post(route('decrypt.aes'), [
            'file' => $encUpload,
            'password' => 'secret',
        ])->assertSessionHas('download_url');
        $dec = session('download_name');

        $this->assertEquals($contents, Storage::disk('local')->get("decrypted/{$dec}"));
    }
}
