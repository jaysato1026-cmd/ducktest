from PIL import Image, ImageDraw, ImageFont

sizes = [16, 24, 32, 48, 64, 128, 256]
images = []

for size in sizes:
    scale = size / 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # soft shadow
    shadow_offset = max(1, int(8 * scale))
    draw.ellipse(
        [int(18 * scale), int(22 * scale) + shadow_offset, int(238 * scale), int(242 * scale) + shadow_offset],
        fill=(0, 0, 0, 70),
    )

    # blue roundel with a simple diagonal arrow
    draw.ellipse([int(18 * scale), int(18 * scale), int(238 * scale), int(238 * scale)], fill=(36, 137, 255, 255))
    draw.ellipse([int(34 * scale), int(28 * scale), int(222 * scale), int(216 * scale)], outline=(120, 203, 255, 110), width=max(1, int(5 * scale)))
    draw.line([int(83 * scale), int(166 * scale), int(164 * scale), int(85 * scale)], fill=(255, 255, 255, 255), width=max(2, int(22 * scale)))
    draw.polygon(
        [
            (int(151 * scale), int(66 * scale)),
            (int(194 * scale), int(62 * scale)),
            (int(190 * scale), int(105 * scale)),
        ],
        fill=(255, 255, 255, 255),
    )

    images.append(image)

images[-1].save("assets/icon.ico", sizes=[(s, s) for s in sizes], append_images=images[:-1])
images[-1].save("assets/icon.png")
