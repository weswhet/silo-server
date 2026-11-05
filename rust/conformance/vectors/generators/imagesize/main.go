// Command imagesize writes rust/conformance/vectors/core/imagesize.json from the real
// internal/imagesize package. Run with rust/conformance/vectors/generators/imagesize/run.sh.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Silo-Server/silo-server/internal/imagesize"
)

type tcase map[string]any

func main() {
	raws := []string{"", " ", "small", "SMALL", " Medium ", "large", "original", "Original\t", "huge", "w500", "width:300", "smal", "\x00", "größe", "\"q\""}
	types := []string{"poster", "backdrop", " BACKDROP ", "still", "thumb", "logo", "banner", "clearart", "profile", "disc", "", "weird"}
	sizes := []imagesize.Size{imagesize.Unset, imagesize.Small, imagesize.Medium, imagesize.Large, imagesize.Original, "bogus", "width:", "width:0", "width:-5", "width:x", "width:+40", "width:9999999999999999999999"}
	for _, px := range []int{1, 100, 299, 300, 301, 499, 500, 501, 1000, 1280, 1281, 1920, 2560, 2561, 7680} {
		sizes = append(sizes, imagesize.Width(px))
	}
	variants := []string{"", "original", "w300", "w500", " w1000 ", "w1280", "w1920", "w2560", "w0", "w-1", "w+500", "wx", "w", "W500", "w9999999999999999999999", "w100"}
	var out []tcase
	for _, r := range raws {
		s, err := imagesize.Parse(r)
		c := tcase{"fn": "parse", "raw": r, "size": string(s)}
		if err != nil {
			c["err"] = err.Error()
		}
		out = append(out, c)
	}
	for _, s := range sizes {
		px, ok := s.TargetWidth()
		out = append(out, tcase{"fn": "size", "size": string(s), "target": px, "ok": ok,
			"plugin": imagesize.PluginVariant(s), "photo": imagesize.PhotoPluginVariant(s)})
		for _, t := range types {
			out = append(out, tcase{"fn": "variant", "type": t, "size": string(s), "out": imagesize.Variant(t, s)})
		}
	}
	for _, v := range variants {
		px, ok := imagesize.VariantWidthPx(v)
		out = append(out, tcase{"fn": "width_px", "variant": v, "px": px, "ok": ok})
		for _, t := range types {
			n, ok := imagesize.NextLower(t, v)
			out = append(out, tcase{"fn": "next_lower", "type": t, "variant": v, "out": n, "ok": ok})
		}
	}
	ws := []imagesize.Widths{{}, {Poster: 300}, {Backdrop: 1920, Photo: 185}, {Poster: 1, Backdrop: 2, Logo: 3, Still: 4, Photo: 5}, {Logo: -4, Still: 780}}
	for _, w := range ws {
		for _, s := range []imagesize.Size{imagesize.Unset, imagesize.Large} {
			req := imagesize.Request{Size: s, Widths: w}
			var fors []string
			for _, slot := range imagesize.Slots {
				fors = append(fors, slot.Name()+"="+string(req.For(slot)))
			}
			out = append(out, tcase{"fn": "widths", "widths": []int{w.Poster, w.Backdrop, w.Logo, w.Still, w.Photo},
				"size": string(s), "encode": w.Encode(), "zero": w.IsZero(), "for": fors})
		}
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(append(b, '\n'))
}
