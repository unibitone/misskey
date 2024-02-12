/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { CALL_HURO_TYPES, CHAR_TILES, FourMentsuOneJyantou, House, MANZU_TILES, PINZU_TILES, SOUZU_TILES, TileType, YAOCHU_TILES, TILE_TYPES, analyzeFourMentsuOneJyantou, isShuntu, isManzu, isPinzu, isSameNumberTile, isSouzu, isKotsu } from './common.js';

const RYUISO_TILES: TileType[] = ['s2', 's3', 's4', 's6', 's8', 'hatsu'];
const KOKUSHI_TILES: TileType[] = ['m1', 'm9', 'p1', 'p9', 's1', 's9', 'e', 's', 'w', 'n', 'haku', 'hatsu', 'chun'];

export const NORMAL_YAKU_NAMES = [
	'riichi',
	'ippatsu',
	'tsumo',
	'tanyao',
	'pinfu',
	'iipeko',
	'field-wind-e',
	'field-wind-s',
	'field-wind-w',
	'field-wind-n',
	'seat-wind-e',
	'seat-wind-s',
	'seat-wind-w',
	'seat-wind-n',
	'white',
	'green',
	'red',
	'rinshan',
	'chankan',
	'haitei',
	'hotei',
	'sanshoku-dojun',
	'sanshoku-doko',
	'ittsu',
	'chanta',
	'chitoitsu',
	'toitoi',
	'sananko',
	'honroto',
	'sankantsu',
	'shosangen',
	'double-riichi',
	'honitsu',
	'junchan',
	'ryampeko',
	'chinitsu',
	'dora',
	'red-dora',
] as const;

export const YAKUMAN_NAMES = [
	'kokushi',
	'kokushi-13',
	'suanko',
	'suanko-tanki',
	'daisangen',
	'tsuiso',
	'shosushi',
	'daisushi',
	'ryuiso',
	'chinroto',
	'sukantsu',
	'churen',
	'churen-9',
	'tenho',
	'chiho',
] as const;

export type YakuName = typeof NORMAL_YAKU_NAMES[number] | typeof YAKUMAN_NAMES[number];

export type EnvForCalcYaku = {
	house: House;

	/**
	 * 和了る人の手牌(副露牌は含まず、ツモ、ロン牌は含む)
	 */
	handTiles: TileType[];

	/**
	 * 河
	 */
	hoTiles: TileType[];

	/**
	 * 副露
	 */
	huros: ({
		type: 'pon';
		tile: TileType;
	} | {
		type: 'cii';
		tiles: [TileType, TileType, TileType];
	} | {
		type: 'ankan';
		tile: TileType;
	} | {
		type: 'minkan';
		tile: TileType;
	})[];

	tsumoTile: TileType;
	ronTile: TileType;

	/**
	 * 場風
	 */
	fieldWind: House;

	/**
	 * 自風
	 */
	seatWind: House;

	/**
	 * リーチしたかどうか
	 */
	riichi: boolean;

	/**
	 * 一巡目以内かどうか
	 */
	ippatsu: boolean;
};

type YakuDefiniyion = {
	name: YakuName;
	upper?: YakuName;
	fan?: number;
	isYakuman?: boolean;
	isDoubleYakuman?: boolean;
	kuisagari?: boolean;
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => boolean;
};

function countTiles(tiles: TileType[], target: TileType): number {
	return tiles.filter(t => t === target).length;
}

export const NORAML_YAKU_DEFINITIONS: YakuDefiniyion[] = [{
	name: 'tsumo',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		// 面前じゃないとダメ
		if (state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type))) return false;

		return state.tsumoTile != null;
	},
}, {
	name: 'riichi',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		return state.riichi;
	},
}, {
	name: 'ippatsu',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		return state.ippatsu;
	},
}, {
	name: 'red',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return (
			(countTiles(state.handTiles, 'chun') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'chun' :
				huro.type === 'ankan' ? huro.tile === 'chun' :
				huro.type === 'minkan' ? huro.tile === 'chun' :
				false).length >= 3)
		);
	},
}, {
	name: 'white',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return (
			(countTiles(state.handTiles, 'haku') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'haku' :
				huro.type === 'ankan' ? huro.tile === 'haku' :
				huro.type === 'minkan' ? huro.tile === 'haku' :
				false).length >= 3)
		);
	},
}, {
	name: 'green',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return (
			(countTiles(state.handTiles, 'hatsu') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'hatsu' :
				huro.type === 'ankan' ? huro.tile === 'hatsu' :
				huro.type === 'minkan' ? huro.tile === 'hatsu' :
				false).length >= 3)
		);
	},
}, {
	name: 'field-wind-e',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.fieldWind === 'e' && (
			(countTiles(state.handTiles, 'e') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'e' :
				huro.type === 'ankan' ? huro.tile === 'e' :
				huro.type === 'minkan' ? huro.tile === 'e' :
				false).length >= 3)
		);
	},
}, {
	name: 'field-wind-s',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.fieldWind === 's' && (
			(countTiles(state.handTiles, 's') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 's' :
				huro.type === 'ankan' ? huro.tile === 's' :
				huro.type === 'minkan' ? huro.tile === 's' :
				false).length >= 3)
		);
	},
}, {
	name: 'seat-wind-e',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.house === 'e' && (
			(countTiles(state.handTiles, 'e') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'e' :
				huro.type === 'ankan' ? huro.tile === 'e' :
				huro.type === 'minkan' ? huro.tile === 'e' :
				false).length >= 3)
		);
	},
}, {
	name: 'seat-wind-s',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.house === 's' && (
			(countTiles(state.handTiles, 's') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 's' :
				huro.type === 'ankan' ? huro.tile === 's' :
				huro.type === 'minkan' ? huro.tile === 's' :
				false).length >= 3)
		);
	},
}, {
	name: 'seat-wind-w',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.house === 'w' && (
			(countTiles(state.handTiles, 'w') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'w' :
				huro.type === 'ankan' ? huro.tile === 'w' :
				huro.type === 'minkan' ? huro.tile === 'w' :
				false).length >= 3)
		);
	},
}, {
	name: 'seat-wind-n',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return state.house === 'n' && (
			(countTiles(state.handTiles, 'n') >= 3) ||
			(state.huros.filter(huro =>
				huro.type === 'pon' ? huro.tile === 'n' :
				huro.type === 'ankan' ? huro.tile === 'n' :
				huro.type === 'minkan' ? huro.tile === 'n' :
				false).length >= 3)
		);
	},
}, {
	name: 'tanyao',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		return (
			(!state.handTiles.some(t => YAOCHU_TILES.includes(t))) &&
			(state.huros.filter(huro =>
				huro.type === 'pon' ? YAOCHU_TILES.includes(huro.tile) :
				huro.type === 'ankan' ? YAOCHU_TILES.includes(huro.tile) :
				huro.type === 'minkan' ? YAOCHU_TILES.includes(huro.tile) :
				huro.type === 'cii' ? huro.tiles.some(t2 => YAOCHU_TILES.includes(t2)) :
				false).length === 0)
		);
	},
}, {
	name: 'pinfu',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		// 面前じゃないとダメ
		if (state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type))) return false;
		// 三元牌はダメ
		if (state.handTiles.some(t => ['haku', 'hatsu', 'chun'].includes(t))) return false;

		// TODO: 両面待ちかどうか

		// 風牌判定(役牌でなければOK)
		if (fourMentsuOneJyantou.head === state.seatWind) return false;
		if (fourMentsuOneJyantou.head === state.fieldWind) return false;

		// 全て順子か？
		if (fourMentsuOneJyantou.mentsus.some((mentsu) => mentsu[0] === mentsu[1])) return false;

		return true;
	},
}, {
	name: 'honitsu',
	fan: 3,
	isYakuman: false,
	kuisagari: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const tiles = state.handTiles;
		let manzuCount = tiles.filter(t => MANZU_TILES.includes(t)).length;
		let pinzuCount = tiles.filter(t => PINZU_TILES.includes(t)).length;
		let souzuCount = tiles.filter(t => SOUZU_TILES.includes(t)).length;
		let charCount = tiles.filter(t => CHAR_TILES.includes(t)).length;

		for (const huro of state.huros) {
			const huroTiles = huro.type === 'cii' ? huro.tiles : huro.type === 'pon' ? [huro.tile, huro.tile, huro.tile] : [huro.tile, huro.tile, huro.tile, huro.tile];
			manzuCount += huroTiles.filter(t => MANZU_TILES.includes(t)).length;
			pinzuCount += huroTiles.filter(t => PINZU_TILES.includes(t)).length;
			souzuCount += huroTiles.filter(t => SOUZU_TILES.includes(t)).length;
			charCount += huroTiles.filter(t => CHAR_TILES.includes(t)).length;
		}

		if (manzuCount > 0 && pinzuCount > 0) return false;
		if (manzuCount > 0 && souzuCount > 0) return false;
		if (pinzuCount > 0 && souzuCount > 0) return false;
		if (charCount === 0) return false;

		return true;
	},
}, {
	name: 'chinitsu',
	fan: 6,
	isYakuman: false,
	kuisagari: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const tiles = state.handTiles;
		let manzuCount = tiles.filter(t => MANZU_TILES.includes(t)).length;
		let pinzuCount = tiles.filter(t => PINZU_TILES.includes(t)).length;
		let souzuCount = tiles.filter(t => SOUZU_TILES.includes(t)).length;
		let charCount = tiles.filter(t => CHAR_TILES.includes(t)).length;

		for (const huro of state.huros) {
			const huroTiles = huro.type === 'cii' ? huro.tiles : huro.type === 'pon' ? [huro.tile, huro.tile, huro.tile] : [huro.tile, huro.tile, huro.tile, huro.tile];
			manzuCount += huroTiles.filter(t => MANZU_TILES.includes(t)).length;
			pinzuCount += huroTiles.filter(t => PINZU_TILES.includes(t)).length;
			souzuCount += huroTiles.filter(t => SOUZU_TILES.includes(t)).length;
			charCount += huroTiles.filter(t => CHAR_TILES.includes(t)).length;
		}

		if (charCount > 0) return false;
		if (manzuCount > 0 && pinzuCount > 0) return false;
		if (manzuCount > 0 && souzuCount > 0) return false;
		if (pinzuCount > 0 && souzuCount > 0) return false;

		return true;
	},
}, {
	name: 'iipeko',
	fan: 1,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		// 面前じゃないとダメ
		if (state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type))) return false;

		// 同じ順子が2つあるか？
		return fourMentsuOneJyantou.mentsus.some((mentsu) =>
			fourMentsuOneJyantou.mentsus.filter((mentsu2) =>
				mentsu2[0] === mentsu[0] && mentsu2[1] === mentsu[1] && mentsu2[2] === mentsu[2]).length >= 2);
	},
}, {
	name: 'toitoi',
	fan: 2,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		if (state.huros.length > 0) {
			if (state.huros.some(huro => huro.type === 'cii')) return false;
		}

		// 全て刻子か？
		if (!fourMentsuOneJyantou.mentsus.every((mentsu) => mentsu[0] === mentsu[1])) return false;

		return true;
	},
}, {
	name: 'sananko',
	fan: 2,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {

	},
}, {
	name: 'sanshoku-dojun',
	fan: 2,
	isYakuman: false,
	kuisagari: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const shuntsus = fourMentsuOneJyantou.mentsus.filter(tiles => isShuntu(tiles));

		for (const shuntsu of shuntsus) {
			if (isManzu(shuntsu[0])) {
				if (shuntsus.some(tiles => isPinzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
					if (shuntsus.some(tiles => isSouzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
						return true;
					}
				}
			} else if (isPinzu(shuntsu[0])) {
				if (shuntsus.some(tiles => isManzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
					if (shuntsus.some(tiles => isSouzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
						return true;
					}
				}
			} else if (isSouzu(shuntsu[0])) {
				if (shuntsus.some(tiles => isManzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
					if (shuntsus.some(tiles => isPinzu(tiles[0]) && isSameNumberTile(tiles[0], shuntsu[0]) && isSameNumberTile(tiles[1], shuntsu[1]) && isSameNumberTile(tiles[2], shuntsu[2]))) {
						return true;
					}
				}
			}
		}

		return false;
	},
}, {
	name: 'sanshoku-doko',
	fan: 2,
	isYakuman: false,
	kuisagari: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const kotsus = fourMentsuOneJyantou.mentsus.filter(tiles => isKotsu(tiles));

		for (const kotsu of kotsus) {
			if (isManzu(kotsu[0])) {
				if (kotsus.some(tiles => isPinzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
					if (kotsus.some(tiles => isSouzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
						return true;
					}
				}
			} else if (isPinzu(kotsu[0])) {
				if (kotsus.some(tiles => isManzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
					if (kotsus.some(tiles => isSouzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
						return true;
					}
				}
			} else if (isSouzu(kotsu[0])) {
				if (kotsus.some(tiles => isManzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
					if (kotsus.some(tiles => isPinzu(tiles[0]) && isSameNumberTile(tiles[0], kotsu[0]))) {
						return true;
					}
				}
			}
		}

		return false;
	},
}, {
	name: 'ittsu',
	fan: 2,
	isYakuman: false,
	kuisagari: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const shuntsus = fourMentsuOneJyantou.mentsus.filter(tiles => isShuntu(tiles));

		if (shuntsus.some(tiles => tiles[0] === 'm1' && tiles[1] === 'm2' && tiles[2] === 'm3')) {
			if (shuntsus.some(tiles => tiles[0] === 'm4' && tiles[1] === 'm5' && tiles[2] === 'm6')) {
				if (shuntsus.some(tiles => tiles[0] === 'm7' && tiles[1] === 'm8' && tiles[2] === 'm9')) {
					return true;
				}
			}
		}
		if (shuntsus.some(tiles => tiles[0] === 'p1' && tiles[1] === 'p2' && tiles[2] === 'p3')) {
			if (shuntsus.some(tiles => tiles[0] === 'p4' && tiles[1] === 'p5' && tiles[2] === 'p6')) {
				if (shuntsus.some(tiles => tiles[0] === 'p7' && tiles[1] === 'p8' && tiles[2] === 'p9')) {
					return true;
				}
			}
		}
		if (shuntsus.some(tiles => tiles[0] === 's1' && tiles[1] === 's2' && tiles[2] === 's3')) {
			if (shuntsus.some(tiles => tiles[0] === 's4' && tiles[1] === 's5' && tiles[2] === 's6')) {
				if (shuntsus.some(tiles => tiles[0] === 's7' && tiles[1] === 's8' && tiles[2] === 's9')) {
					return true;
				}
			}
		}

		return false;
	},
}, {
	name: 'chitoitsu',
	fan: 2,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (state.huros.length > 0) return false;
		const countMap = new Map<TileType, number>();
		for (const tile of state.handTiles) {
			const count = (countMap.get(tile) ?? 0) + 1;
			countMap.set(tile, count);
		}
		return Array.from(countMap.values()).every(c => c === 2);
	},
}, {
	name: 'shosangen',
	fan: 2,
	isYakuman: false,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const kotsuTiles = fourMentsuOneJyantou.mentsus.filter(tiles => isKotsu(tiles)).map(tiles => tiles[0]);

		for (const huro of state.huros) {
			if (huro.type === 'cii') {
				// nop
			} else if (huro.type === 'pon') {
				kotsuTiles.push(huro.tile);
			} else {
				kotsuTiles.push(huro.tile);
			}
		}

		switch (fourMentsuOneJyantou.head) {
			case 'haku': return kotsuTiles.includes('hatsu') && kotsuTiles.includes('chun');
			case 'hatsu': return kotsuTiles.includes('haku') && kotsuTiles.includes('chun');
			case 'chun': return kotsuTiles.includes('haku') && kotsuTiles.includes('hatsu');
		}

		return false;
	},
}];

export const YAKUMAN_DEFINITIONS: YakuDefiniyion[] = [{
	name: 'daisangen',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const kotsuTiles = fourMentsuOneJyantou.mentsus.filter(tiles => isKotsu(tiles)).map(tiles => tiles[0]);

		for (const huro of state.huros) {
			if (huro.type === 'cii') {
				// nop
			} else if (huro.type === 'pon') {
				kotsuTiles.push(huro.tile);
			} else {
				kotsuTiles.push(huro.tile);
			}
		}

		return kotsuTiles.includes('haku') && kotsuTiles.includes('hatsu') && kotsuTiles.includes('chun');
	},
}, {
	name: 'shosushi',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		let all = [...state.handTiles];
		for (const huro of state.huros) {
			if (huro.type === 'cii') {
				all = [...all, ...huro.tiles];
			} else if (huro.type === 'pon') {
				all = [...all, huro.tile, huro.tile, huro.tile];
			} else {
				all = [...all, huro.tile, huro.tile, huro.tile, huro.tile];
			}
		}

		switch (fourMentsuOneJyantou.head) {
			case 'e': return (countTiles(all, 's') === 3) && (countTiles(all, 'w') === 3) && (countTiles(all, 'n') === 3);
			case 's': return (countTiles(all, 'e') === 3) && (countTiles(all, 'w') === 3) && (countTiles(all, 'n') === 3);
			case 'w': return (countTiles(all, 'e') === 3) && (countTiles(all, 's') === 3) && (countTiles(all, 'n') === 3);
			case 'n': return (countTiles(all, 'e') === 3) && (countTiles(all, 's') === 3) && (countTiles(all, 'w') === 3);
		}

		return false;
	},
}, {
	name: 'daisushi',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const kotsuTiles = fourMentsuOneJyantou.mentsus.filter(tiles => isKotsu(tiles)).map(tiles => tiles[0]);

		for (const huro of state.huros) {
			if (huro.type === 'cii') {
				// nop
			} else if (huro.type === 'pon') {
				kotsuTiles.push(huro.tile);
			} else {
				kotsuTiles.push(huro.tile);
			}
		}

		return kotsuTiles.includes('e') && kotsuTiles.includes('s') && kotsuTiles.includes('w') && kotsuTiles.includes('n');
	},
}, {
	name: 'tsuiso',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		const tiles = state.handTiles;
		let manzuCount = tiles.filter(t => MANZU_TILES.includes(t)).length;
		let pinzuCount = tiles.filter(t => PINZU_TILES.includes(t)).length;
		let souzuCount = tiles.filter(t => SOUZU_TILES.includes(t)).length;

		for (const huro of state.huros) {
			const huroTiles = huro.type === 'cii' ? huro.tiles : huro.type === 'pon' ? [huro.tile, huro.tile, huro.tile] : [huro.tile, huro.tile, huro.tile, huro.tile];
			manzuCount += huroTiles.filter(t => MANZU_TILES.includes(t)).length;
			pinzuCount += huroTiles.filter(t => PINZU_TILES.includes(t)).length;
			souzuCount += huroTiles.filter(t => SOUZU_TILES.includes(t)).length;
		}

		if (manzuCount > 0 || pinzuCount > 0 || souzuCount > 0) return false;

		return true;
	},
}, {
	name: 'ryuiso',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		if (state.handTiles.some(t => !RYUISO_TILES.includes(t))) return false;

		for (const huro of state.huros) {
			const huroTiles = huro.type === 'cii' ? huro.tiles : huro.type === 'pon' ? [huro.tile, huro.tile, huro.tile] : [huro.tile, huro.tile, huro.tile, huro.tile];
			if (huroTiles.some(t => !RYUISO_TILES.includes(t))) return false;
		}

		return true;
	},
}, {
	name: 'churen-9',
	isYakuman: true,
	isDoubleYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		// 面前じゃないとダメ
		if (state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type))) return false;

		const agariTile = state.tsumoTile ?? state.ronTile;
		const tempaiTiles = [...state.handTiles];
		tempaiTiles.splice(state.handTiles.indexOf(agariTile), 1);

		if (isManzu(agariTile)) {
			if ((countTiles(tempaiTiles, 'm1') === 3) && (countTiles(tempaiTiles, 'm9') === 3)) {
				if (tempaiTiles.includes('m2') && tempaiTiles.includes('m3') && tempaiTiles.includes('m4') && tempaiTiles.includes('m5') && tempaiTiles.includes('m6') && tempaiTiles.includes('m7') && tempaiTiles.includes('m8')) {
					return true;
				}
			}
		} else if (isPinzu(agariTile)) {
			if ((countTiles(tempaiTiles, 'p1') === 3) && (countTiles(tempaiTiles, 'p9') === 3)) {
				if (tempaiTiles.includes('p2') && tempaiTiles.includes('p3') && tempaiTiles.includes('p4') && tempaiTiles.includes('p5') && tempaiTiles.includes('p6') && tempaiTiles.includes('p7') && tempaiTiles.includes('p8')) {
					return true;
				}
			}
		} else if (isSouzu(agariTile)) {
			if ((countTiles(tempaiTiles, 's1') === 3) && (countTiles(tempaiTiles, 's9') === 3)) {
				if (tempaiTiles.includes('s2') && tempaiTiles.includes('s3') && tempaiTiles.includes('s4') && tempaiTiles.includes('s5') && tempaiTiles.includes('s6') && tempaiTiles.includes('s7') && tempaiTiles.includes('s8')) {
					return true;
				}
			}
		}

		return false;
	},
}, {
	name: 'churen',
	upper: 'churen-9',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		if (fourMentsuOneJyantou == null) return false;

		// 面前じゃないとダメ
		if (state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type))) return false;

		if (isManzu(state.handTiles[0])) {
			if ((countTiles(state.handTiles, 'm1') === 3) && (countTiles(state.handTiles, 'm9') === 3)) {
				if (state.handTiles.includes('m2') && state.handTiles.includes('m3') && state.handTiles.includes('m4') && state.handTiles.includes('m5') && state.handTiles.includes('m6') && state.handTiles.includes('m7') && state.handTiles.includes('m8')) {
					return true;
				}
			}
		} else if (isPinzu(state.handTiles[0])) {
			if ((countTiles(state.handTiles, 'p1') === 3) && (countTiles(state.handTiles, 'p9') === 3)) {
				if (state.handTiles.includes('p2') && state.handTiles.includes('p3') && state.handTiles.includes('p4') && state.handTiles.includes('p5') && state.handTiles.includes('p6') && state.handTiles.includes('p7') && state.handTiles.includes('p8')) {
					return true;
				}
			}
		} else if (isSouzu(state.handTiles[0])) {
			if ((countTiles(state.handTiles, 's1') === 3) && (countTiles(state.handTiles, 's9') === 3)) {
				if (state.handTiles.includes('s2') && state.handTiles.includes('s3') && state.handTiles.includes('s4') && state.handTiles.includes('s5') && state.handTiles.includes('s6') && state.handTiles.includes('s7') && state.handTiles.includes('s8')) {
					return true;
				}
			}
		}

		return false;
	},
}, {
	name: 'kokushi',
	isYakuman: true,
	calc: (state: EnvForCalcYaku, fourMentsuOneJyantou: FourMentsuOneJyantou | null) => {
		return KOKUSHI_TILES.every(t => state.handTiles.includes(t));
	},
}];

export function calcYakus(state: EnvForCalcYaku): YakuName[] {
	const oneHeadFourMentsuPatterns: (FourMentsuOneJyantou | null)[] = analyzeFourMentsuOneJyantou(state.handTiles);
	if (oneHeadFourMentsuPatterns.length === 0) oneHeadFourMentsuPatterns.push(null);

	const yakumanPatterns = oneHeadFourMentsuPatterns.map(fourMentsuOneJyantou => {
		const matchedYakus: YakuDefiniyion[] = [];
		for (const yakuDef of YAKUMAN_DEFINITIONS) {
			if (yakuDef.upper && matchedYakus.some(yaku => yaku.name === yakuDef.upper)) continue;
			const matched = yakuDef.calc(state, fourMentsuOneJyantou);
			if (matched) {
				matchedYakus.push(yakuDef);
			}
		}
		return matchedYakus;
	}).filter(yakus => yakus.length > 0);

	if (yakumanPatterns.length > 0) {
		return yakumanPatterns[0].map(yaku => yaku.name);
	}

	const yakuPatterns = oneHeadFourMentsuPatterns.map(fourMentsuOneJyantou => {
		return NORAML_YAKU_DEFINITIONS.map(yakuDef => {
			const result = yakuDef.calc(state, fourMentsuOneJyantou);
			return result ? yakuDef : null;
		}).filter(yaku => yaku != null) as YakuDefiniyion[];
	}).filter(yakus => yakus.length > 0);

	const isMenzen = state.huros.some(huro => CALL_HURO_TYPES.includes(huro.type));

	let maxYakus = yakuPatterns[0];
	let maxFan = 0;
	for (const yakus of yakuPatterns) {
		let fan = 0;
		for (const yaku of yakus) {
			if (yaku.kuisagari && !isMenzen) {
				fan += yaku.fan! - 1;
			} else {
				fan += yaku.fan!;
			}
		}
		if (fan > maxFan) {
			maxFan = fan;
			maxYakus = yakus;
		}
	}

	return maxYakus.map(yaku => yaku.name);
}
