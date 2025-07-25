package elligator

import (
	"fmt"
	"testing"
)

func TestFeInvert(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		x, want *fieldElement
	}{
		{
			x:    feFromHex("1fdabb681a533e5c40a2bd8a41cce53e00dac69911cbcb15c015998a56e17470"),
			want: feFromHex("64862d9e85146e22bf10ec835a375238bfb8ba45bbca12a11d236dec34e85bf0"),
		},
		{
			x:    feFromHex("fca4003dbd57560c1a480d2ee3b2badc5b53eaafc175b5d6f067468133853ecc"),
			want: feFromHex("77c09e9aee85123775e4339fb0e0fbea811c6dd0f03c043be32aaaf79317cfa2"),
		},
		{
			x:    feFromHex("4473dc50155ac13645750235bcef87342eb4a83a5f53e3bd1de903fbc9deb35c"),
			want: feFromHex("101a587ec25377af1a54285e4e4cdfeb46ccfff17824c7836f9d853b6ee1f9ad"),
		},
		{
			x:    feFromHex("7db0365ebf272f717872d511e8a513c1566365aa9adb45fa5a828b3172a99fac"),
			want: feFromHex("00c1657e6f821eece6a435b1065e844094e32ba56489cd3d13188b8a147289a1"),
		},
		{
			x:    feFromHex("37afad3e25c250b547f9029c1ac5f2a6e3b0159493f000668ed7998a0041ba03"),
			want: feFromHex("2291fdf3fe3abb9a6dfc624a6a1835c67a37de4581690fc949ae4f8f19e2a755"),
		},
		{
			x:    feFromHex("347a7a7de806697603d45e9b8a6771d078ad5333ca2e4c9ce369d0a6b46e9b9d"),
			want: feFromHex("75d506bae18923872af8f434bc73d55420269b732b2fa31cc695015462e3ebd8"),
		},
		{
			x:    feFromHex("2e5aa9db5ca7e78a7f5223fedb0a7a895d54722345692a0938b2f8a93e9ccf73"),
			want: feFromHex("eb0176137c6651d9bc314f451ba7fd7882c19ff9b5e5f59652b6397e8bdb3ac5"),
		},
		{
			x:    feFromHex("4e597cf5994a0393cfab4b6e0e7392eeca409ba1cce62d9dd74d9ea64115b65a"),
			want: feFromHex("4c89c2b1448ac9122b9241d6aa6c22beed5e1037947ef57fe688d480568857b4"),
		},
		{
			x:    feFromHex("d432871dfdd5d01569a163a35e12a40ab46da4d1a3b9c65cfae4e7bd654211b7"),
			want: feFromHex("fbc4beb3d5fe003822989c290b30a195bf16cf8d7e05e6fc5ee6e7bdcd154078"),
		},
		{
			x:    feFromHex("ca20b1014fceafeb71b7d86e58b8d5caa86f8059f3218edf85251b84470cef1b"),
			want: feFromHex("3b47c7acb2ce7e9d9747f6402112d4f2f9c9e77e379d0aa4240dc05c0336e49c"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("feInvert(%s)", test.x), func(t *testing.T) {
			t.Parallel()

			if got, want := new(fieldElement).Invert(test.x), test.want; !got.Equal(want) {
				t.Errorf("feInvert(%s) = %s, want = %s", test.x, got, want)
			}
		})
	}
}

func TestFeSqrt(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		x, want *fieldElement
	}{
		{
			x:    feFromHex("743a004100e76a1de51b190d316eda1dbb6d2b9bb1082aca0034a168f8fc9461"),
			want: nil,
		},
		{
			x:    feFromHex("f6c0af4f1d2e6e86194f4711d1edbfa07329d7886faf4396607323b0af186734"),
			want: nil,
		},
		{
			x:    feFromHex("bec1e5a7c5ce5d08c1b0d3301e86ef5fec1a2ccec305e22e1b7aec5bf4845809"),
			want: feFromHex("6b60f243c48bb13408ea83d48e93dd82909ff2e68dd0270eda858248962b9d9a"),
		},
		{
			x:    feFromHex("80b8325a8df5a1921035272ef2a580833cb492244f2cb536071a2b482a81d016"),
			want: nil,
		},
		{
			x:    feFromHex("23f01c63fd3aff5940c48319417eb316bd5b7aa9add204a31604dd9c81368bc6"),
			want: nil,
		},
		{
			x:    feFromHex("95dec40812c0df5e50368e2fe9b73c4775c9819aaf4e5612190dcf90a1a4da19"),
			want: feFromHex("b9ae368667f9e5a4defbd9e1b2bede87a179c48a065e36314d3c7a47c8d9d111"),
		},
		{
			x:    feFromHex("df1ae93085b744df0e4ac8a0e9b00aa34ae2e5ecf43716dd12d603d66dec1218"),
			want: feFromHex("0e1449c0d2e8e282f6e15ced0828476594298db2dc9b83cac4c7fbc1567060d3"),
		},
		{
			x:    feFromHex("2c7ea58b58661a80e94aab235c3da563ca02a7ea9f003b518a409fc9c313eb42"),
			want: nil,
		},
		{
			x:    feFromHex("4121db9b0c5649e16b516c83393366ed98f40a30f0907abc94c3bea326608252"),
			want: feFromHex("3e4cda1fd6e27c9407a8498c69812fbaee24bfed9c7aba30572f24b1089f3919"),
		},
		{
			x:    feFromHex("09fd2028bfb2cf2bb1ca8ea13e0580243541665f0db25520464afe813332ed78"),
			want: nil,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("feSqrt(%s)", test.x), func(t *testing.T) {
			t.Parallel()

			got, want := new(fieldElement).Sqrt(test.x), test.want
			switch {
			case got != nil && want == nil:
				t.Errorf("feSqrt(%s) = %s, want nil", test.x, got)
			case got == nil && want != nil:
				t.Errorf("feSqrt(%s) = nil, want %s", test.x, want)
			case got != nil && want != nil && !got.Equal(want):
				t.Errorf("feSqrt(%s) = %s, want = %s", test.x, got, want)
			}
		})
	}
}
