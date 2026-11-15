package esipa

import (
	"bytes"
	"errors"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/openiotrsp/openiotrsp/storage"
)

// errPPRNotAllowed is SGP.32 "8.2.8 PPR – 1.2 Not Allowed" (pprNotAllowed).
var errPPRNotAllowed = errors.New("esipa: profile policy rules are not allowed")

const profileClassOperational int64 = 2

// pprBit1 and pprBit2 are SGP.22 PprIds. Bit 0 (pprUpdateControl) has no
// meaning on StoreMetadataRequest and is ignored.
const (
	pprBit1 = 1
	pprBit2 = 2
)

type operatorID struct {
	mccMnc  []byte
	gid1    []byte
	gid1Set bool
	gid2    []byte
	gid2Set bool
}

type pparRule struct {
	ppr1      bool
	ppr2      bool
	operators []operatorID
}

// verifyProfileMetadata applies SGP.22 §3.1.3 steps 7c and 8, using the RAT
// rules in §2.9.2.1. Step 7a (an LPAd that refuses PPRs on a removable eUICC)
// does not apply: the eIM is performing the check. consentRequired does not
// reject a download; ESipa has no end-user prompt, and the PPE ignores that flag.
// A profile counts as operational only when its stored class is operational(2).
func verifyProfileMetadata(meta *bertlv.TLV, rat []byte, profiles []storage.ProfileState) error {
	if meta == nil {
		return nil
	}
	rulesNode := meta.First(tagProfilePolicy)
	if rulesNode == nil || (!bitSet(rulesNode.Value, pprBit1) && !bitSet(rulesNode.Value, pprBit2)) {
		return nil
	}
	if bitSet(rulesNode.Value, pprBit1) && operationalProfileInstalled(profiles) {
		return errPPRNotAllowed
	}
	rules, err := parseRAT(rat)
	if err != nil {
		return errPPRNotAllowed
	}
	owner, ok := parseOperator(meta.First(tagProfileOwner))
	if !ok {
		return errPPRNotAllowed
	}
	if bitSet(rulesNode.Value, pprBit1) && !pprAllowed(pprBit1, owner, rules) {
		return errPPRNotAllowed
	}
	if bitSet(rulesNode.Value, pprBit2) && !pprAllowed(pprBit2, owner, rules) {
		return errPPRNotAllowed
	}
	return nil
}

func operationalProfileInstalled(profiles []storage.ProfileState) bool {
	for _, profile := range profiles {
		if profile.ProfileClass != nil && *profile.ProfileClass == profileClassOperational {
			return true
		}
	}
	return false
}

func pprAllowed(bit int, owner operatorID, rules []pparRule) bool {
	for _, rule := range rules {
		applies := bit == pprBit1 && rule.ppr1 || bit == pprBit2 && rule.ppr2
		if !applies {
			continue
		}
		for _, allowed := range rule.operators {
			if operatorMatch(allowed, owner) {
				return true
			}
		}
	}
	return false
}

func operatorMatch(rule, owner operatorID) bool {
	if !nibbleMatch(rule.mccMnc, owner.mccMnc) {
		return false
	}
	return gidMatch(rule.gid1Set, rule.gid1, owner.gid1Set, owner.gid1) &&
		gidMatch(rule.gid2Set, rule.gid2, owner.gid2Set, owner.gid2)
}

func nibbleMatch(rule, owner []byte) bool {
	if len(rule) != 3 || len(owner) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		for _, shift := range []uint{4, 0} {
			left := (rule[i] >> shift) & 0x0f
			right := (owner[i] >> shift) & 0x0f
			if left != 0x0e && left != right {
				return false
			}
		}
	}
	return true
}

func gidMatch(ruleSet bool, rule []byte, ownerSet bool, owner []byte) bool {
	if !ruleSet {
		return !ownerSet
	}
	if len(rule) == 0 {
		return true
	}
	return ownerSet && bytes.Equal(rule, owner)
}

func parseRAT(raw []byte) ([]pparRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	tlv, err := parseRelayTLV(raw)
	if err != nil {
		return nil, err
	}
	nodes := tlv.Children
	if len(nodes) == 1 && nodes[0].Tag.Equal(tagSequence) && sequenceOfRules(nodes[0]) {
		nodes = nodes[0].Children
	}
	rules := make([]pparRule, 0, len(nodes))
	for _, node := range nodes {
		if !node.Tag.Equal(tagSequence) {
			continue
		}
		rule, ok := parsePPAR(node)
		if ok {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func sequenceOfRules(node *bertlv.TLV) bool {
	if node == nil || len(node.Children) == 0 {
		return false
	}
	for _, child := range node.Children {
		if !child.Tag.Equal(tagSequence) {
			return false
		}
	}
	return true
}

func parsePPAR(node *bertlv.TLV) (pparRule, bool) {
	var ids, operators *bertlv.TLV
	for _, child := range node.Children {
		if ids == nil && (child.Tag.Equal(bertlv.Universal.Primitive(3)) || child.Tag.Equal(bertlv.ContextSpecific.Primitive(0))) {
			ids = child
			continue
		}
		if operators == nil && (child.Tag.Equal(bertlv.ContextSpecific.Constructed(1)) || child.Tag.Equal(tagSequence)) {
			operators = child
		}
	}
	if ids == nil {
		return pparRule{}, false
	}
	return pparRule{
		ppr1:      bitSet(ids.Value, pprBit1),
		ppr2:      bitSet(ids.Value, pprBit2),
		operators: parseOperators(operators),
	}, true
}

func parseOperators(node *bertlv.TLV) []operatorID {
	if node == nil {
		return nil
	}
	var out []operatorID
	for _, child := range node.Children {
		if op, ok := parseOperator(child); ok {
			out = append(out, op)
		}
	}
	return out
}

func parseOperator(node *bertlv.TLV) (operatorID, bool) {
	if node == nil {
		return operatorID{}, false
	}
	body := node
	if inner := node.First(tagSequence); inner != nil {
		body = inner
	}
	var op operatorID
	var octets [][]byte
	for _, child := range body.Children {
		switch {
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(0)):
			op.mccMnc = cloneBytes(child.Value)
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(1)):
			op.gid1 = cloneBytes(child.Value)
			op.gid1Set = true
		case child.Tag.Equal(bertlv.ContextSpecific.Primitive(2)):
			op.gid2 = cloneBytes(child.Value)
			op.gid2Set = true
		case child.Tag.Equal(tagOctetString):
			octets = append(octets, cloneBytes(child.Value))
		}
	}
	if len(op.mccMnc) == 0 && len(octets) > 0 {
		op.mccMnc = octets[0]
		if len(octets) > 1 {
			op.gid1 = octets[1]
			op.gid1Set = true
		}
		if len(octets) > 2 {
			op.gid2 = octets[2]
			op.gid2Set = true
		}
	}
	if len(op.mccMnc) != 3 {
		return operatorID{}, false
	}
	return op, true
}
