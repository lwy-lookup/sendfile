/*
* Copyright (c) 2020 AIIT Ubiquitous Team
* XiUOS is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*        http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
* See the Mulan PSL v2 for more details.
*/

/**
* @file ecc.c
* @brief arithmetic in ecc
* @version 1.0 
* @author AIIT Ubiquitous Team
* @date 2021-04-24
*/
#include "ecc.h"

/**
 * @brief Print the point(x, y)
 * 
 * @param point pointer of a point in group G1.
 * 
 * @return null
 */
void G1pointPrint(G1point *point)
{
	Big8wPrint(&point->x);
	Big8wPrint(&point->y);
}
/**
 * @brief judge whether the point in group G1
 * 
 * @param point a point(x, y)
 * 
 * @return true if point in group G1; else false
 * 
 */
bool PointInG1(G1point point)
{
	big8w y_power2;
	big8w temp;

	y_power2 = Big8wMultMod(point.y, point.y, curve.q); // y^2 mod curve.q

	temp = Big8wMultMod(point.x, point.x, curve.q);
	temp = Big8wMultMod(temp, point.x, curve.q); // x^3

	temp = Big8wAddMod(temp, curve.b, curve.q); // x^3 + b

	return Big8wEqual(&y_power2, &temp);
}
/**
 * 
 * @brief compute the sum of two points in group G1; set infinite point O as (0, 0), tell if exist O before points add.
 *        Calls: big8wIszero, Big8wEqual, Big8wAddMod, Big8wMinusMod, Big8wReverse
 *        Called By: G1pointMult
 * 
 * @param point1 the first point in group G1, affine
 * @param point2 the second point in group G1, affine
 * 
 * @return a point in group
 * 
 */
G1point G1pointAdd(G1point point1, G1point point2)
{
	G1point ret;
	big8w lambda, temp;

	// infinite point
	if (Big8wIsZero(&point1.x) && Big8wIsZero(&point1.y))
		return point2;
	else if (Big8wIsZero(&point1.x) && Big8wIsZero(&point1.y))
		return point1;

	if (Big8wEqual(&point1.x, &point2.x)) {

		if (!Big8wEqual(&point1.y, &point2.y)){ // x1=x2, y1 != y2(y1 = -y2), ret = O (0, 0)
			memset(ret.x.word, 0x00, BIG8W_BYTESIZE);
			memset(ret.y.word, 0x00, BIG8W_BYTESIZE);
			return ret;
		}

		temp = Big8wAddMod(point1.y, point1.y, curve.q); // 2*y1
		temp = Big8wReverse(temp, curve.q); // 1/2*y1
		temp = Big8wMultMod(point1.x, temp, curve.q); // x1*(1/2*y1)
		temp = Big8wMultMod(point1.x, temp, curve.q); // x1*x1*(1/2*y1)
		lambda = Big8wAddMod(temp, Big8wAddMod(temp, temp, curve.q), curve.q); // 3*x1*x1*(1/2*y1)
	} 
	else {
		temp = Big8wMinusMod(point1.x, point2.x, curve.q);
		temp = Big8wReverse(temp, curve.q); // 1/(x2 - x1)

		lambda = Big8wMinusMod(point1.y, point2.y, curve.q); // y2 - y1
		lambda = Big8wMultMod(temp, lambda, curve.q);
	}

	ret.x = Big8wMultMod(lambda, lambda, curve.q); // k*k
	temp = Big8wAddMod(point1.x, point2.x, curve.q); // x1 + x2
	ret.x = Big8wMinusMod(ret.x, temp, curve.q); // x3 = lambda*lambda - x1 - x2

	ret.y = Big8wMinusMod(point1.x, ret.x, curve.q); // y3 = lambda*(x1 - x3) - y1
	ret.y = Big8wMultMod(lambda, ret.y, curve.q);
	ret.y = Big8wMinusMod(ret.y, point1.y, curve.q);

	return ret;
}
/**
 * @brief convert G1point of affine to Jacobi
 * 
 * @param point G1point, affine
 * 
 * @result ret, Jacobi, set z = 1
 * 
 */
ecn G1pointToEcn(G1point point)
{
	ecn ret;

	ret.x = point.x;
	ret.y = point.y;
	memset(&(ret.z), 0x00, BIG8W_BYTESIZE);
	ret.z.word[0] = 1;

	return ret;
}
/**
 * @brief convert G1point of ecn to affine
 * 
 * @param point G1point, Jacobi
 * 
 * @result ret, G1point, affine
 * 
 */
G1point EcnToG1point(ecn point)
{
	big8w temp;
	G1point ret;

	point.z = Big8wReverse(point.z, curve.q);
	temp = Big8wMultMod(point.z, point.z, curve.q);
	ret.x = Big8wMultMod(point.x, temp, curve.q);
	ret.y = Big8wMultMod(point.y, Big8wMultMod(temp, point.z, curve.q), curve.q);

	return ret;
}
/**
 * @brief add of two points in group G1, Jacobi
 * 
 * @param point1 the first point in group G1, Jacobi 
 * @param point2 the second point in group G1, Jacobi
 * 
 * @return ret, a point in group G1
 * 
 */
ecn G1PointAddEcn(ecn point1, ecn point2, bool doubleflag)
{
	big8w A, B, C, D, E;
	ecn ret;

	memset(&A, 0x00, BIG8W_BYTESIZE);

	if (doubleflag){
		if (Big8wIsZero(&(point1.z)))
			return point1;
		A = Big8wMultMod(point1.y, point1.y, curve.q);

		B = Big8wAddMod(point1.x, point1.x, curve.q);
		B = Big8wAddMod(B, B, curve.q);
		B = Big8wMultMod(A, B, curve.q);

		C = Big8wMultMod(A, A, curve.q);
		C = Big8wAddMod(C, C, curve.q);
		C = Big8wAddMod(C, C, curve.q);
		C = Big8wAddMod(C, C, curve.q);

		D = Big8wMultMod(point1.x, point1.x, curve.q);
		D = Big8wAddMod(D, Big8wAddMod(D, D, curve.q), curve.q);

		E = Big8wMultMod(point1.z, point1.z, curve.q);

		ret.x = Big8wMultMod(D, D, curve.q);
		ret.x = Big8wMinusMod(ret.x, Big8wAddMod(B, B, curve.q), curve.q);

		ret.y = Big8wMinusMod(B, ret.x, curve.q);
		ret.y = Big8wMultMod(ret.y, D, curve.q);
		ret.y = Big8wMinusMod(ret.y, C, curve.q);

		ret.z = Big8wMultMod(point1.y, point1.z, curve.q);
		ret.z = Big8wAddMod(ret.z, ret.z, curve.q);

		return ret;
	}

	else{
		if (Big8wIsZero(&(point1.z)))
			return point2;
		else if (Big8wIsZero(&(point2.z)))
			return point1;
		else if (Big8wEqual(&(point1.x), &(point2.x))){
			memset(&(ret.z), 0x00, BIG8W_BYTESIZE);
			return ret;
		}

		big8w F, G, H, I;

		A = Big8wMultMod(point1.z, point1.z, curve.q);
		B = Big8wMultMod(A, point1.z, curve.q);
		C = Big8wMultMod(point2.x, A, curve.q);
		D = Big8wMultMod(B, point2.y, curve.q);
		E = Big8wMinusMod(C, point1.x, curve.q);
		F = Big8wMinusMod(D, point1.y, curve.q);
		G = Big8wMultMod(E, E, curve.q);
		H = Big8wMultMod(G, E, curve.q);
		I = Big8wMultMod(point1.x, G, curve.q);

		ret.x = Big8wMultMod(F, F, curve.q);
		ret.x = Big8wMinusMod(ret.x, H, curve.q);
		ret.x = Big8wMinusMod(ret.x, Big8wAddMod(I, I, curve.q), curve.q);

		ret.y = Big8wMultMod(F, Big8wMinusMod(I, ret.x, curve.q), curve.q);
		ret.y = Big8wMinusMod(ret.y, Big8wMultMod(point1.y, H, curve.q), curve.q);

		ret.z = Big8wMultMod(point1.z, E, curve.q);

		return ret;
	}
}

/**
 * 
 * @brief mult point; scan bits of bignum
 * 
 * @param bignum big number; 
 * @param point point in group G1, Jacobi
 * 
 * @return a point in group G1
 * 
 */
ecn G1pointMultEcn(big8w bignum, ecn point)
{
	bool flag = 0;
	int i;
	int index;
	uint32_t elem;
	ecn ret = point, temp = point;

	Big8wHighestbit(&bignum, &i, &index);
	elem = bignum.word[i];
	
	index--;
	while (index>=0) { 
		flag = (elem >> (index--)) & 1;
		ret = G1PointAddEcn(temp, temp, true); 
		if (flag)
			ret = G1PointAddEcn(ret, point, false); 
		temp = ret;
	}

	i--; 
	for (; i>=0; i--) {
		elem = bignum.word[i];
		index = 31;
		while (index>=0) {
			flag = (elem >> (index--)) & 1;
			ret = G1PointAddEcn(temp, temp, true); 
			if (flag)
				ret = G1PointAddEcn(ret, point, false); 
			temp = ret;
		}
	}

	return ret;
}
/**
 * @brief mult point in group G1. (num * point)
 * 
 * @param num big number 
 * @param point point in group G1, affine
 * 
 * @return ret, a point in group G1
 * 
 */
G1point G1pointMult(big8w bignum, G1point point)
{
	G1point ret;
	ecn ecn_p;

	ecn_p = G1pointToEcn(point);
	ecn_p = G1pointMultEcn(bignum, ecn_p);
	ret = EcnToG1point(ecn_p);

	if (!PointInG1(ret))
		printf("PointMult error, point not in G1\n");

	return ret;
}