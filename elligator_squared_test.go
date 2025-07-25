package elligator

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"testing"
)

func Example() {
	// Generate a P-256 ECDH key pair.
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Encode the public key.
	encoded, err := Encode(k.PublicKey().Bytes(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Decode the public key.
	qP, err := Decode(encoded)
	if err != nil {
		panic(err)
	}

	// Compare the two.
	fmt.Println(bytes.Equal(k.PublicKey().Bytes(), qP))
	// Output: true
}

func BenchmarkEncode(b *testing.B) {
	// Use CSHAKE128 as a deterministic source of "random" data to allow for deterministic benchmarking.
	prng := sha3.NewCSHAKE128([]byte("elligator-squared-p256-benchmark"), nil)

	k, err := ecdh.P256().GenerateKey(prng)
	if err != nil {
		b.Fatal(err)
	}
	p := k.PublicKey().Bytes()

	for b.Loop() {
		if _, err := Encode(p, prng); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	e, err := hex.DecodeString("d63d2829acfae73ecf9ba818dfd0431fd1ba6c459d54db40bc5500220268e6279ac94968d2c32fe46e1ca3db1dba72b86eafa0857865c01fe63d62b718789e80")
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if _, err := Decode(e); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	for i := 0; i < 1_000; i++ {
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		encoded, err := Encode(k.PublicKey().Bytes(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		q, err := Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := q, k.PublicKey().Bytes(); !bytes.Equal(got, want) {
			t.Fatalf("Decode(%x) = %x, want = %x", encoded, got, want)
		}
	}
}

func TestG(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		x, want *fieldElement
	}{
		{
			x:    &one,
			want: feFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d26049"),
		},
		{
			x:    &two,
			want: feFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604d"),
		},
		{
			x:    feFromHex("4077f2bde92bfa027151a7412d6e92ba0c035eb58dc8c86b4f659536c36b47d5"),
			want: feFromHex("2819ec852c134ff7a481d7adbc3f1a085bc9f6b250a5917a822703f191f3ea4d"),
		},
		{
			x:    feFromHex("dbf9ace2b5d50a2974d1227c37571235055b3ceccc5b075d0a7dccb571a0e497"),
			want: feFromHex("72bde2e2f464bbcb043d01e6901f8949b90a9167775cf278990a1a31d321a691"),
		},
		{
			x:    feFromHex("49a25b63783bc98313dc9590892d74a4e6ef2daac04910d9a84ba0c45f62ba37"),
			want: feFromHex("58e94d66dc3b8bb3a6e07fa7998e38084b9a374eb4da29b70d26f7c77531b287"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("g(%s)", test.x), func(t *testing.T) {
			t.Parallel()
			if got, want := g(test.x), test.want; !got.Equal(want) {
				t.Errorf("g(%s) = %s, want = %s", test.x, got, want)
			}
		})
	}
}

func TestX0(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		x, want *fieldElement
	}{
		{
			x:    feFromHex("cb2943cf0b5476a59d206e7fe380e8b135a02db4733db3d158fd55636ccf899b"),
			want: feFromHex("c5f4959fc0f7067b69974b5d9efcf923305935912ab99c5831b99da67f1900e6"),
		},
		{
			x:    feFromHex("392a2a37ff8ef4d55f22b1d7683c3c597a07dbd587ae26d446bb92e8d740a3d8"),
			want: feFromHex("a27be5e04212e6e71db063f8d42e470938405b33164fc1c62e12251f5e1fe106"),
		},
		{
			x:    feFromHex("95e5053c38c001e4abbc20701a2ce7bde00bc21e945b61cbd18759c2a3d520c5"),
			want: feFromHex("27e445195a1958cc6bdb6010cdf2225781ce4a40ffd65798f1d3c7cc0f5d5979"),
		},
		{
			x:    feFromHex("43978799b731aed92b92c3d07c1f2060e552eaedc024f1686dd547dc8d5b3d83"),
			want: feFromHex("b66058282f37a19fac62ffdc3353cfbc8d2a79124ed149ad9882d25c0441c109"),
		},
		{
			x:    feFromHex("25ed83e1ef078e5bf999b77c252873797146eeea53eb127093acb64097a929ad"),
			want: feFromHex("3da6debc73df325e25873929d3110646f598ea12cf346f0ac6032ab94096953e"),
		},
		{
			x:    feFromHex("76aa61bd4c008daf6dde17f5a88e8131e6529187c09407ba86bd14448f334270"),
			want: feFromHex("591e27ad76d5be879d8c8fd756155687751d29a710079c25d35f2a47ff000dff"),
		},
		{
			x:    feFromHex("29c6dffcce6132eb0554561072d7d05d410b8c351f07c500d9d6ce034e5cadda"),
			want: feFromHex("d100c5674f2b0a43f153981bcbca3b79402ceced78e4f95b1b5b45fff66b0253"),
		},
		{
			x:    feFromHex("0d891a4ee7d34246ce7dbf5d8905d088a2708e8111fad4b54248848ce45f5211"),
			want: feFromHex("1f32e00e2c393a9ea863c63d4058af10691b9c0efccb2bc874736e2b51638ca7"),
		},
		{
			x:    feFromHex("113a2a45d36ed4a056660d9a616469cc642ce6ce7afffdb9fd5d2191d3eb5940"),
			want: feFromHex("260fca36f5fd3ea11fd7e03b29476cd878b9fe021718ddc5475cb747db34b63e"),
		},
		{
			x:    feFromHex("65562cec98b8b4def060db947dc9152d3f0282dc365c6dcbe86fbad6ecccd088"),
			want: feFromHex("0643980e0a08f4f0e196ebfd07b22c46b27dbc4c4003dbf56c1640c6ad5519e0"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("x_0(%s)", test.x), func(t *testing.T) {
			t.Parallel()
			if got, want := x0(test.x), test.want; !got.Equal(want) {
				t.Errorf("x_0(%s) = %s, want = %s", test.x, got, want)
			}
		})
	}
}

func TestX1(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		x, want *fieldElement
	}{
		{
			x:    feFromHex("bdd250da6bd46362873bbb7479263c3fdf3007f09b23646bb523b36250de95a2"),
			want: feFromHex("f67e0bf48295c68945959628d26e2d61f5aaaa51dbe1201d889cd6b40a44f283"),
		},
		{
			x:    feFromHex("7440eb92ec8a5b06be6cb1e7db2ba4e93012931fe2d10398cb739633ea0ab797"),
			want: feFromHex("6b23a7dddab608e323cb34108c13b034343414ef59c583c6d26c0a528fadedbf"),
		},
		{
			x:    feFromHex("d5d5ddbac418d9c479cda8d2f59fb81f65294b29a1c783307df948099194f0d9"),
			want: feFromHex("29cbaa4f8733df0326f44d8c8eacec5f7e1b3884cbee361cf6e96a0927672fd9"),
		},
		{
			x:    feFromHex("a85bfacf9af92864a125709eed04b5f6f1c76f84e16aafd4d931d049177b6f26"),
			want: feFromHex("bb0ddea97cdd6d57e6060525d6e9781b0cae283b7abfb924809283f5fa11e200"),
		},
		{
			x:    feFromHex("4df7a4e4f51c500cd110a56395275a2e36c272a6f4fe6a2c0def5f0e33a91e62"),
			want: feFromHex("63c69a3928a4febc7ece597fb31e56227d32a53580d9516a2951499869459d4a"),
		},
		{
			x:    feFromHex("05b4af58b9613f6e2d8d47cb1135f1d09bf1a5571f1877f4878ae3dd06bd168c"),
			want: feFromHex("d9c63ebe1be4911b47ebe174cc99dab661c035afbb08badec47e53b7c92c2b5f"),
		},
		{
			x:    feFromHex("dadb5a5bdc1f8dd946de072e7d38abc03d7ea175775409fae8a23a1017675a94"),
			want: feFromHex("0f363dfd9aba34f981bfa241a1986f4c48af75770987898bcba4eb70a611f4e2"),
		},
		{
			x:    feFromHex("a2498d3dc802ee753d814ff8822afab15cd3fddff488abff46ea8c01b32579dd"),
			want: feFromHex("7d381226f433f548d56f1ebcadafeb83ab100819d9b29c952362bb87f3993b60"),
		},
		{
			x:    feFromHex("f2cd2e0850e38c08b0a029b9bcb72a4a98c03045fbde2bd000eb3a1418575975"),
			want: feFromHex("89f984ec24e0221409fb77d4c5f68010e15102bf46099d52c99749a00dcea42a"),
		},
		{
			x:    feFromHex("723b70f2a8ac8b49dac17a36f0f1f90e24beb2ec5f78e3d8553b837ed7856266"),
			want: feFromHex("193a9c2714883a2310d191c722379aced9f06fc61f4bae094edaf211ac825ad0"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("x_1(%s)", test.x), func(t *testing.T) {
			t.Parallel()
			if got, want := x1(test.x), test.want; !got.Equal(got) {
				t.Errorf("x_1(%s) = %s, want = %s", test.x, got, want)
			}
		})
	}
}

func TestF(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		u, x, y *fieldElement
	}{
		{
			u: feFromHex("87789ed27e8a8078b283bc0f755af77e74a47755d25a6afb10be866b89297696"),
			x: feFromHex("a054c994d3538c7ab3f325b3dfcb743991869cbf9b136cd78cea7a484208433e"),
			y: feFromHex("c5c664c9341db26132486565fb0169ce8a24f4ec1598b09d5b1441f658395779"),
		},
		{
			u: feFromHex("8c73f5f6e30d54b5f119d1ad9de4f24157aaab701bb724fc01c93457da680bcb"),
			x: feFromHex("26d80e7bcdf004cde2b1ab530f12eff2526c26c25be64e64a6639177a3e7dd32"),
			y: feFromHex("5cc49c52d1c6c83ddcefa1d21d9c6ce126c618ae2773398c0940ffc9c1960e20"),
		},
		{
			u: feFromHex("7e0e9901aa67574a613432a54c1e9be9192b30556fedd69f778f7e259a74b929"),
			x: feFromHex("e8809ecf13bb5de7b1ec4c44e45d0f4447e69708f3467cf4507851043cd548b7"),
			y: feFromHex("06369669d6b4722672fa1bee48fb73ed07d2aa5a691938fb711a1395fe9421f0"),
		},
		{
			u: feFromHex("b05fda93d519726e785db2e990e8908dee50d69aa557a3beea56171108e2e8d6"),
			x: feFromHex("1e1e5d73554203269ccc12afb174a2cc3c082e9dd35ca19813704b707e8ec525"),
			y: feFromHex("eef17e6bfedf7c58f6565bac7e9e3552b76e093b127d1b01d292e33a56016261"),
		},
		{
			u: feFromHex("995b72f5b47654ed00af806d46f36b2002e82a4810196c79931cd18381ea7a47"),
			x: feFromHex("3ade7bd63cf6e0cf9ad85e0ac46ed0b6cd21b82e885ffaf11cfd5cafda6d279e"),
			y: feFromHex("b5ad932a6dbdab8dd76f1be9a702a4fa395816e70dac4190ccde9394fd4e5795"),
		},
		{
			u: feFromHex("af3432feb8945d7523586b9a3f0ac70367579cd055e9410e002f6017e151baaa"),
			x: feFromHex("0a7549e3f575c1547239727a98fe8ba94dc96e004853beb66a951eb9fdb5b8a5"),
			y: feFromHex("39c1934d73648b6217af2de4325fb637bfc5771ca6913a3a8c7f7f6d289d35f3"),
		},
		{
			u: feFromHex("78d6cc6490a28ce13bfd1a3617a4ca271ba3547f0c649a9c12148835f6456d6f"),
			x: feFromHex("5ff0e184e4e9a55c9960c00f16ea36a1f8223093bf97559f5994a4934b4d266c"),
			y: feFromHex("da9a9b34cdc048c7b4d11be543d7d5a7d7969a02c9f5960a45ab303e7135f62a"),
		},
		{
			u: feFromHex("209a7a8b88dbfa8b042064020d9549414d0f2b7e2ca61031a83848c5cd7edf80"),
			x: feFromHex("a3eb60ee110f0544b9c99395a3f201f196b8d739d19b61bd7dba7214a6e0be60"),
			y: feFromHex("72c75184a034da408b6f2c7f4c8c0132bd2595f38d86898c148c730b289b8550"),
		},
		{
			u: feFromHex("251102e9077d60fa9e1d69ee01c24109f3b0c68e3fc933dad1a83f6891770440"),
			x: feFromHex("cb9519b2440de85d517a373c3a3187ac654f4a8cd156db4bf1272c613d00276a"),
			y: feFromHex("432004f5fe3ff509f6ee8dbd25f1ad59528624853c46b43e9d925b18d312fdc9"),
		},
		{
			u: feFromHex("8814cc19005dc1d05e26518869388abb39c4fbfd6ed93e81b355762f8b55d9ea"),
			x: feFromHex("93aff2b3d6aa61fd0c70a83556d0ffca2f24c2ae2e95ee010588eeeed5e93c84"),
			y: feFromHex("ef3b58a72afa62042df1637407840e58b29ab94f226666b6774edd96c836ea32"),
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("f(%s)", test.u), func(t *testing.T) {
			t.Parallel()
			gotX, gotY := f(test.u)
			if !gotX.Equal(test.x) || !gotY.Equal(gotY) {
				t.Errorf("f(%s) = (%s, %s), want = (%s, %s)", test.u, gotX, gotY, test.x, test.y)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		x, want string
	}{
		{
			x:    "6dab76bdcab43eb44959c0c57dd4f771625177a2f41bb407797a2d6a0ec64db011d88d5ec0faff56e1acba5c00e9fe317de9a3ac95c1421dc01bae9248a0e910",
			want: "04083c0f5503e23eaabca86f32cbf603eb1fbb037701b9bf94d053ce57a84e367cf2e282d17fd64220c64c9fe12e347971b86760d30821f75cdae9bfb0294ab5df",
		},
		{
			x:    "39e8af2c9d255428a7e7cf8b98059451ed49fd89f550dc2221738fa83c1015b64eea07d779fa52cc3ad50fdb8620da352712bc51e9e561bee17bc9d2e628f266",
			want: "04db78e1a639cb19deaee75a62a88da16efa776f339cd6cac8d7f1fadf93c8e8405b4e8291a9e4d46677d7e25f66ae3dcdcdcb568ad7f5850ee5dc5dfd4b9d6620",
		},
		{
			x:    "b13041611796aad2608538a088bbce53b7794ed8d2c7586337eec0d067ff7bf776781e689e1768f65ee2146edfc4ffaa51bda50ad84c5f8cc3662783f1250712",
			want: "04f9f6dbbb2cfa228e0ea43c75559d423dd2ddfd793ca0d6eb33e2ac67461d82ef9e5aaac6a27441e216db395fe2985776d451255c19f7039826195b124c516d58",
		},
		{
			x:    "37d2ae5538d441b23681550f6014922758184f3cc62b54fd0c038f19fc76aa00fe7cae32f06d4fc1aaf6a65cd15b9d58be48f6b3e62d5929c3b1bf62ad7d2c0f",
			want: "041130a8d0fbc8182df8329f163d7e95a2dd8e92ae34eb1f10aee6434d30b6f3d00c04fc2f16f9c9fa1fa858e14d87632827c930495ca2d00b441f4f9139bde577",
		},
		{
			x:    "23dbc9d9404d088840841c1b1d501514e730b1135ac5dcbac36fb43ec21265c6bd62f065356ba21726062b9f3c18b04deda4347dabce888865842fcfcbbe9e30",
			want: "0486918545b2e651ec95c7c973c9e0e821b345b4c638fb197fa6af70bae23b8871f3a7b5c8605304cb018c1380f6f88c49bab0f6cd2ffa296c8d1cfb9cd8938dda",
		},
		{
			x:    "33515a7579f28af148e8521d9d9293c62503c825167cf2dfcc5f37abe2a531a3d95e4247f931e387743505ac6b50c8e65c1817c2c648457cb77743cdfec3267e",
			want: "0437718f9fcdaa3d3e2e3d52f5da33610a327aa859f1a71acb5c3b367def71a81d9609d57351b22d5d3d9b59c502a023658fca33ea9670c32c5bf59391f30ef900",
		},
		{
			x:    "daa995f294a201a29e46fc49dc2a576285e8841aae8ceb5b673923c7c735123220a464a600b1e9fbc38696bafe44e8517b76d601d75795aee2597ca4778de4fe",
			want: "04d420b0263099d74a07f48e45c3f9ca446dad63dbcfdb956c220036c2c17fe4cc1765608b3a04925d406d60ab1d003da21b000a50937f6c9e6f643e1b05a1e977",
		},
		{
			x:    "b33b932fe4121ad817db33cb5f9875ecd845d340d3e27274e6c7cb19e81f1454e36c5be5d301fcfec4c4f0d4488d48eadbacff75ae9ec72e513cebb7edbf7ee2",
			want: "041b71329bbe87d4040b4a636596d2e715d2e9317aea1c98dcf3af8b2bf11859401ec4c81fa4ec0f983388457a574dc4da154e6f7b29b617c3cb2c8113c54e7eb4",
		},
		{
			x:    "84204fb69149775bca9e5481221bc694b38d84b37255e3f4273e67275cf5c35264725f9b9121e05a7f91fd19b242e74ea1b0cb12aae0aa2e18a35be45877a11a",
			want: "0490fab5975dd5d4b4c1cc517b4ca1b15d7705729fa54667a45ee760bcb83b5b9cc3a41c2bf38e1a44cd1204287f4aa4e549f638fa677f7cdb02ea3977fee41ce7",
		},
		{
			x:    "465dbe10735a2a019d7d48efa6c96ff262a06478f3024dc3d38552956d74d8213283fd22bcd3b2432f2fc2f7a2313e1e5b13c44ff018c45089c47cb2f2413fda",
			want: "0480f21f22b85b8acf54e878227540fc34e74f5b67da801d123890b5a02a386299d2158a81318befb98129cb9a582aa1795f2d5ca43025db08c0f6006e16006b06",
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("Decode(%s)", test.x), func(t *testing.T) {
			t.Parallel()
			b, err := hex.DecodeString(test.x)
			if err != nil {
				t.Fatal(err)
			}

			p, err := Decode(b)
			if err != nil && test.want != "" {
				t.Fatal(err)
			}

			if got := hex.EncodeToString(p); p != nil && got != test.want {
				t.Errorf("Decode(%s) = %s, want = %s", test.x, got, test.want)
			}
		})
	}
}
