package x509

import (
	"encoding/asn1"
	"testing"
)

func TestAns(t *testing.T) {
	result, _ := asn1.Marshal(oidNamedCurveP256SM2)

	print(result)
}
