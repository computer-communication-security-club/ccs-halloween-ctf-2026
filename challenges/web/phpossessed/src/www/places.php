<?php
declare(strict_types=1);

function seed_places(): array
{
    return [
        ['id' => 'choijin-lama', 'location' => 'Choijin Lama Temple', 'region' => 'Ulaanbaatar, Mongolia', 'title' => 'An echo behind the temple doors', 'category' => 'Temple', 'author' => 'PHPossessed editors', 'status' => 'FICTIONAL SAMPLE', 'image' => 'https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/Choijin_lama_temple_museum_%281%29_%282551100718%29.jpg/960px-Choijin_lama_temple_museum_%281%29_%282551100718%29.jpg', 'photo_author' => 'Francisco Anzola', 'photo_source' => 'https://commons.wikimedia.org/wiki/File:Choijin_lama_temple_museum_(1)_(2551100718).jpg', 'photo_license' => 'CC BY 2.0', 'photo_license_url' => 'https://creativecommons.org/licenses/by/2.0/', 'caption' => 'A guardian statue in Choijin Lama Temple Museum. Photo by Francisco Anzola; displayed with a dark color treatment and crop.', 'account' => "In this fictional field report, a visitor pauses outside the quiet courtyard. A low chant seems to follow them toward the gate, then stops as the city traffic returns. No one else in the story hears it.\n\nThe real museum preserves the heritage of Mongolia’s state oracle. Its religious history is context for this imagined story, not evidence of a haunting.", 'source' => 'https://templemuseum.mn/en/templemuseum?page=musein-tuuh', 'source_label' => 'Museum history · Choijin Lama Temple Museum'],
        ['id' => 'erdene-zuu', 'location' => 'Erdene Zuu Monastery', 'region' => 'Kharkhorin, Övörkhangai, Mongolia', 'title' => 'Footsteps along the white wall', 'category' => 'Monastery', 'author' => 'PHPossessed editors', 'status' => 'FICTIONAL SAMPLE', 'image' => 'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c3/202408_Erdene_Zuu_Monastery_01.jpg/1280px-202408_Erdene_Zuu_Monastery_01.jpg', 'photo_author' => 'Jonashtand', 'photo_source' => 'https://commons.wikimedia.org/wiki/File:202408_Erdene_Zuu_Monastery_01.jpg', 'photo_license' => 'CC BY-SA 4.0', 'photo_license_url' => 'https://creativecommons.org/licenses/by-sa/4.0/', 'caption' => 'Erdene Zuu Monastery near Karakorum, August 2024. Photo by Jonashtand; displayed with a dark color treatment and crop.', 'account' => "An imagined traveler hears a second set of footsteps beside the monastery wall. Each time they stop, the other footsteps take one more step. At the corner, there is only wind and empty ground.\n\nThis is an original fictional story set near a real heritage site. It is not a local testimony or a claim about the monastery’s religious community.", 'source' => 'https://www.wmf.org/monuments/choijin-lama-temple', 'source_label' => 'Heritage context · World Monuments Fund'],
        ['id' => 'gobi-death-worm', 'location' => 'The Gobi Desert', 'region' => 'Southern Mongolia', 'title' => 'The legend beneath the sand', 'category' => 'Desert', 'author' => 'PHPossessed editors', 'status' => 'FOLKLORE', 'image' => 'https://upload.wikimedia.org/wikipedia/commons/thumb/d/db/Just_before_the_sandstorm_%2820356218832%29.jpg/1280px-Just_before_the_sandstorm_%2820356218832%29.jpg', 'photo_author' => 'Rob Oo', 'photo_source' => 'https://commons.wikimedia.org/wiki/File:Just_before_the_sandstorm_(20356218832).jpg', 'photo_license' => 'CC BY 2.0', 'photo_license_url' => 'https://creativecommons.org/licenses/by/2.0/', 'caption' => 'Just before the sandstorm, Khongoryn Els, Mongolia. Photo by Rob Oo; displayed with a dark color treatment and crop.', 'account' => "The olgoi-khorkhoi, often called the Mongolian death worm, belongs to the folklore of the Gobi. Stories describe a red, worm-like creature hidden beneath the desert, with a touch or venom said to be deadly.\n\nThe tale became widely known through explorer Roy Chapman Andrews’s writing. Searches have not established that the creature exists. This entry records a legend associated with a broad region, not a verified encounter or a precise sighting location.", 'source' => 'https://apnews.com/article/22426b638b79e06b1aa997125e72abd3', 'source_label' => 'Folklore account · Associated Press'],
    ];
}

function storage_dir(): string
{
    $dir = sys_get_temp_dir() . '/phpossessed-reports';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('The registry is unavailable. Please try again later.');
    }
    return $dir;
}

function submitted_places(): array
{
    $file = storage_dir() . '/reports.json';
    if (!is_file($file)) return [];
    $handle = fopen($file, 'r');
    if ($handle === false) throw new RuntimeException('The registry could not be read.');
    try {
        if (!flock($handle, LOCK_SH)) throw new RuntimeException('The registry is busy.');
        return json_decode(stream_get_contents($handle), true, 512, JSON_THROW_ON_ERROR);
    } finally {
        fclose($handle);
    }
}

function all_places(): array
{
    return array_merge(array_reverse(submitted_places()), seed_places());
}

function place_cards(array $places): string
{
    $html = '<div class="place-grid">';
    foreach ($places as $place) {
        $html .= '<a class="place-card" href="/place/' . h($place['id']) . '"><div class="card-image"><img src="' . h($place['image']) . '" alt="' . h($place['location']) . '" loading="lazy"><span class="badge">' . h($place['status']) . '</span></div><div class="card-body"><p class="eyebrow">' . h($place['region']) . '</p><h3>' . h($place['location']) . '</h3><p>' . h($place['title']) . '</p><span class="read-link">Open case file ↗</span></div></a>';
    }
    return $html . '</div>';
}

function save_place(array $fields, array $upload): array
{
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Choose a JPG, PNG or WebP picture up to 1 MB. Please reselect the picture if an upload failed.');
    }
    $tmp = $upload['tmp_name'] ?? '';
    if (!is_uploaded_file($tmp) || filesize($tmp) > 1024 * 1024) {
        throw new RuntimeException('The picture must be no larger than 1 MB.');
    }
    $info = @getimagesize($tmp);
    $extensions = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    if (!$info || !isset($extensions[$mime]) || ($info['mime'] ?? '') !== $mime || $info[0] > 8000 || $info[1] > 8000) {
        throw new RuntimeException('Use a valid JPG, PNG or WebP picture, at most 8000 pixels on either side.');
    }
    $dir = storage_dir();
    $handle = fopen($dir . '/reports.lock', 'c+');
    if ($handle === false) throw new RuntimeException('The registry is unavailable.');
    $imagePath = null;
    try {
        if (!flock($handle, LOCK_EX)) throw new RuntimeException('The registry is busy.');
        $json = is_file($dir . '/reports.json') ? file_get_contents($dir . '/reports.json') : '';
        $reports = $json === '' ? [] : json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $bytes = array_sum(array_map('filesize', glob($dir . '/*.{jpg,png,webp}', GLOB_BRACE) ?: []));
        if (count($reports) >= 100 || $bytes + filesize($tmp) > 6 * 1024 * 1024) {
            throw new RuntimeException('The registry is full. Please try again after the next reset.');
        }
        $id = bin2hex(random_bytes(12));
        $filename = $id . '.' . $extensions[$mime];
        $imagePath = $dir . '/' . $filename;
        if (!move_uploaded_file($tmp, $imagePath)) throw new RuntimeException('The picture could not be saved.');
        $place = array_merge($fields, ['id' => $id, 'status' => 'UNVERIFIED', 'image' => '/photo/' . $filename, 'caption' => 'Picture submitted by ' . $fields['author'] . '. This account has not been independently verified.', 'filed' => time()]);
        $reports[] = $place;
        $encoded = json_encode($reports, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
        if (file_put_contents($dir . '/reports.pending', $encoded) !== strlen($encoded) || !rename($dir . '/reports.pending', $dir . '/reports.json')) {
            throw new RuntimeException('The report could not be saved.');
        }
        return $place;
    } catch (Throwable $error) {
        if ($imagePath !== null) @unlink($imagePath);
        throw $error;
    } finally {
        fclose($handle);
    }
}
