//go:build gocompat_vectors

package main

import (
	"math"
	"math/rand/v2"
	"strconv"
)

type floatCase struct {
	Bits string `json:"bits"`
	Fmt  string `json:"fmt"`
	Prec int    `json:"prec"`
	Size int    `json:"size"`
	Out  string `json:"out"`
}

type strconvVector struct {
	Meta
	Quote       []mapCase   `json:"quote"`
	FormatFloat []floatCase `json:"format_float"`
}

// tieFloat64 returns dyadic values whose exact expansion can end in a 5 one digit past the shortest
// round-tripping form, where the choice between two equally close candidates shows.
func tieFloat64(r *rand.Rand) float64 {
	return math.Ldexp(float64(r.Int64N(1<<53)|1), -r.IntN(14))
}

func tieFloat32(r *rand.Rand) float32 {
	return float32(math.Ldexp(float64(r.Int64N(1<<24)|1), -r.IntN(8)))
}

func randomFloat(r *rand.Rand) float64 {
	switch r.IntN(10) {
	case 8:
		return tieFloat64(r)
	case 9:
		return float64(tieFloat32(r))
	case 0:
		return math.Float64frombits(r.Uint64())
	case 1:
		return float64(r.Int64N(1 << 53))
	case 2:
		return float64(r.Int64N(100000)) / []float64{2, 4, 8, 10, 100, 1000, 1024}[r.IntN(7)]
	case 3:
		return math.Pow(10, float64(r.IntN(640)-320))
	case 4:
		return float64(r.Int64N(1000000)) * math.Pow(10, float64(r.IntN(50)-25))
	case 5:
		return float64(math.Float32frombits(r.Uint32()))
	case 6:
		return r.Float64()
	}
	return r.Float64() * math.Pow(2, float64(r.IntN(200)-100))
}

var interestingFloats = []float64{
	0, math.Copysign(0, -1), 1, -1, 0.5, 1.5, 2.5, 3.5, 0.125, 0.375, 0.25, 0.75, 1.25, 1.35, 2.675, 1.005, 1e21, 1e20, 9.999999999999999e20, 1e-6, 9.99e-7, 1e-7, 1e-5, 1e-4, 0.001, 120, 7200, 7200.5, 0.1, 0.2, 0.3, 0.1 + 0.2,
	100, 1000, 123456789, 1e15, 1e16, 1e17, 1e22, 1e23, 5e-324, 2.2250738585072014e-308, 2.225073858507201e-308, math.MaxFloat64, math.SmallestNonzeroFloat64, float64(math.MaxFloat32), float64(math.SmallestNonzeroFloat32),
	math.Inf(1), math.Inf(-1), math.NaN(), 1 << 53, 1<<53 + 2, 1 << 63, 1e100, 1.7976931348623157e308, 4.9406564584124654e-324, 33554432, 16777216, 16777217, 3.4e38, 1.17549435e-38, 1e-45,
	999.9995, 999.9994, 9.5, 99.5, 9.95, 0.95, 0.05, 0.005, 0.0005, 0.5e-3, 5, 50, 500, 25, 250, 15, 150, 1.15, 1.25, 1.45,
}

func genStrconv() strconvVector {
	r := newRand(5)
	v := strconvVector{Meta: newMeta()}
	inputs := []string{"", "abc", `a"b`, `a\b`, "\a\b\f\n\r\t\v", "\x00", "\x7f", "é", "日本語", "🎬", "\u00a0", "\u00ad", "\u0085", "\u2028", "\u200b", "\ufeff", "\ufffd", "\U0010ffff", "\U000e0001", "\ufffe", "'"}
	for _, c := range adversarialRunes {
		inputs = append(inputs, string(c))
	}
	inputs = append(inputs, invalidUTF8...)
	for c := rune(0); c < 0x180; c++ {
		inputs = append(inputs, string(c))
	}
	for range 400 {
		inputs = append(inputs, randomAdversarial(r, 5))
	}
	for range 100 {
		inputs = append(inputs, randomBytes(r, 4))
	}
	for _, s := range inputs {
		v.Quote = append(v.Quote, mapCase{S(s), S(strconv.Quote(s))})
	}

	add := func(f float64, fmtByte byte, prec, size int) {
		if size == 32 {
			f = float64(float32(f))
		}
		v.FormatFloat = append(v.FormatFloat, floatCase{strconv.FormatUint(math.Float64bits(f), 16), string(fmtByte), prec, size, strconv.FormatFloat(f, fmtByte, prec, size)})
	}
	for _, f := range interestingFloats {
		for _, fmtByte := range []byte{'f', 'e', 'g', 'E', 'G'} {
			for _, prec := range []int{-1, 0, 1, 2, 3, 6, 10, 17, 25} {
				add(f, fmtByte, prec, 64)
			}
			add(f, fmtByte, -1, 32)
			add(f, fmtByte, 3, 32)
		}
	}
	for range 1500 {
		add(tieFloat64(r), []byte{'f', 'e', 'g'}[r.IntN(3)], -1, 64)
		add(float64(tieFloat32(r)), []byte{'f', 'e', 'g'}[r.IntN(3)], -1, 32)
	}
	for range 3000 {
		f := randomFloat(r)
		switch r.IntN(6) {
		case 0, 1:
			add(f, 'f', -1, 64)
		case 2:
			add(f, 'f', []int{0, 1, 2, 3, 6}[r.IntN(5)], 64)
		case 3:
			add(f, 'g', -1, 64)
		case 4:
			add(f, 'e', -1, 64)
		case 5:
			add(f, []byte{'f', 'e', 'g'}[r.IntN(3)], -1, 32)
		}
	}
	return v
}
