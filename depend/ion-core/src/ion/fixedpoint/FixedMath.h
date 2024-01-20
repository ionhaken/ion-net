﻿/*
 * Copyright 2023 Markus Haikonen, Ionhaken
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once
#include <ion/Base.h>
#include <ion/tracing/Log.h>
#include <ion/fixedpoint/FixedPoint.h>
#include <ion/util/Math.h>
#include <ion/util/Bits.h>


namespace ion
{
#if ION_CONFIG_REAL_IS_FIXED_POINT
constexpr const size_t NumSinEntries = 1024;
constexpr const int16_t gSinValues[NumSinEntries] = {
  0 /*0.000000*/,		99 /*0.006042*/,	  200 /*0.012207*/,		300 /*0.018311*/,
  401 /*0.024475*/,		501 /*0.030579*/,	  602 /*0.036743*/,		702 /*0.042847*/,
  803 /*0.049011*/,		903 /*0.055115*/,	  1004 /*0.061279*/,	1104 /*0.067383*/,
  1204 /*0.073486*/,	1304 /*0.079590*/,	  1405 /*0.085754*/,	1504 /*0.091797*/,
  1605 /*0.097961*/,	1704 /*0.104004*/,	  1805 /*0.110168*/,	1905 /*0.116272*/,
  2004 /*0.122314*/,	2105 /*0.128479*/,	  2204 /*0.134521*/,	2304 /*0.140625*/,
  2403 /*0.146667*/,	2503 /*0.152771*/,	  2601 /*0.158752*/,	2701 /*0.164856*/,
  2800 /*0.170898*/,	2899 /*0.176941*/,	  2998 /*0.182983*/,	3097 /*0.189026*/,
  3195 /*0.195007*/,	3294 /*0.201050*/,	  3392 /*0.207031*/,	3491 /*0.213074*/,
  3589 /*0.219055*/,	3687 /*0.225037*/,	  3785 /*0.231018*/,	3882 /*0.236938*/,
  3980 /*0.242920*/,	4077 /*0.248840*/,	  4175 /*0.254822*/,	4272 /*0.260742*/,
  4369 /*0.266663*/,	4465 /*0.272522*/,	  4562 /*0.278442*/,	4658 /*0.284302*/,
  4755 /*0.290222*/,	4851 /*0.296082*/,	  4947 /*0.301941*/,	5042 /*0.307739*/,
  5138 /*0.313599*/,	5234 /*0.319458*/,	  5329 /*0.325256*/,	5424 /*0.331055*/,
  5518 /*0.336792*/,	5613 /*0.342590*/,	  5707 /*0.348328*/,	5802 /*0.354126*/,
  5895 /*0.359802*/,	5989 /*0.365540*/,	  6082 /*0.371216*/,	6176 /*0.376953*/,
  6268 /*0.382568*/,	6362 /*0.388306*/,	  6454 /*0.393921*/,	6546 /*0.399536*/,
  6638 /*0.405151*/,	6730 /*0.410767*/,	  6822 /*0.416382*/,	6913 /*0.421936*/,
  7004 /*0.427490*/,	7095 /*0.433044*/,	  7186 /*0.438599*/,	7275 /*0.444031*/,
  7366 /*0.449585*/,	7455 /*0.455017*/,	  7545 /*0.460510*/,	7633 /*0.465881*/,
  7722 /*0.471313*/,	7810 /*0.476685*/,	  7899 /*0.482117*/,	7987 /*0.487488*/,
  8075 /*0.492859*/,	8161 /*0.498108*/,	  8249 /*0.503479*/,	8336 /*0.508789*/,
  8422 /*0.514038*/,	8508 /*0.519287*/,	  8594 /*0.524536*/,	8680 /*0.529785*/,
  8764 /*0.534912*/,	8849 /*0.540100*/,	  8933 /*0.545227*/,	9018 /*0.550415*/,
  9101 /*0.555481*/,	9185 /*0.560608*/,	  9268 /*0.565674*/,	9351 /*0.570740*/,
  9433 /*0.575745*/,	9515 /*0.580750*/,	  9596 /*0.585693*/,	9678 /*0.590698*/,
  9759 /*0.595642*/,	9839 /*0.600525*/,	  9920 /*0.605469*/,	9999 /*0.610291*/,
  10079 /*0.615173*/,	10158 /*0.619995*/,	  10237 /*0.624817*/,	10315 /*0.629578*/,
  10393 /*0.634338*/,	10470 /*0.639038*/,	  10548 /*0.643799*/,	10624 /*0.648438*/,
  10701 /*0.653137*/,	10776 /*0.657715*/,	  10852 /*0.662354*/,	10927 /*0.666931*/,
  11002 /*0.671509*/,	11076 /*0.676025*/,	  11150 /*0.680542*/,	11224 /*0.685059*/,
  11296 /*0.689453*/,	11369 /*0.693909*/,	  11441 /*0.698303*/,	11513 /*0.702698*/,
  11584 /*0.707031*/,	11655 /*0.711365*/,	  11725 /*0.715637*/,	11796 /*0.719971*/,
  11865 /*0.724182*/,	11934 /*0.728394*/,	  12003 /*0.732605*/,	12071 /*0.736755*/,
  12138 /*0.740845*/,	12206 /*0.744995*/,	  12273 /*0.749084*/,	12339 /*0.753113*/,
  12405 /*0.757141*/,	12470 /*0.761108*/,	  12536 /*0.765137*/,	12600 /*0.769043*/,
  12664 /*0.772949*/,	12727 /*0.776794*/,	  12791 /*0.780701*/,	12853 /*0.784485*/,
  12915 /*0.788269*/,	12977 /*0.792053*/,	  13038 /*0.795776*/,	13098 /*0.799438*/,
  13159 /*0.803162*/,	13218 /*0.806763*/,	  13278 /*0.810425*/,	13336 /*0.813965*/,
  13394 /*0.817505*/,	13452 /*0.821045*/,	  13509 /*0.824524*/,	13566 /*0.828003*/,
  13622 /*0.831421*/,	13678 /*0.834839*/,	  13732 /*0.838135*/,	13787 /*0.841492*/,
  13841 /*0.844788*/,	13895 /*0.848083*/,	  13948 /*0.851318*/,	14000 /*0.854492*/,
  14052 /*0.857666*/,	14104 /*0.860840*/,	  14154 /*0.863892*/,	14205 /*0.867004*/,
  14255 /*0.870056*/,	14304 /*0.873047*/,	  14353 /*0.876038*/,	14401 /*0.878967*/,
  14449 /*0.881897*/,	14496 /*0.884766*/,	  14542 /*0.887573*/,	14588 /*0.890381*/,
  14634 /*0.893188*/,	14679 /*0.895935*/,	  14723 /*0.898621*/,	14767 /*0.901306*/,
  14810 /*0.903931*/,	14853 /*0.906555*/,	  14895 /*0.909119*/,	14936 /*0.911621*/,
  14978 /*0.914185*/,	15018 /*0.916626*/,	  15058 /*0.919067*/,	15097 /*0.921448*/,
  15136 /*0.923828*/,	15174 /*0.926147*/,	  15212 /*0.928467*/,	15249 /*0.930725*/,
  15285 /*0.932922*/,	15321 /*0.935120*/,	  15356 /*0.937256*/,	15391 /*0.939392*/,
  15425 /*0.941467*/,	15459 /*0.943542*/,	  15492 /*0.945557*/,	15524 /*0.947510*/,
  15556 /*0.949463*/,	15588 /*0.951416*/,	  15618 /*0.953247*/,	15648 /*0.955078*/,
  15678 /*0.956909*/,	15707 /*0.958679*/,	  15735 /*0.960388*/,	15763 /*0.962097*/,
  15790 /*0.963745*/,	15816 /*0.965332*/,	  15842 /*0.966919*/,	15867 /*0.968445*/,
  15892 /*0.969971*/,	15916 /*0.971436*/,	  15940 /*0.972900*/,	15963 /*0.974304*/,
  15985 /*0.975647*/,	16007 /*0.976990*/,	  16028 /*0.978271*/,	16049 /*0.979553*/,
  16069 /*0.980774*/,	16088 /*0.981934*/,	  16107 /*0.983093*/,	16125 /*0.984192*/,
  16142 /*0.985229*/,	16159 /*0.986267*/,	  16175 /*0.987244*/,	16191 /*0.988220*/,
  16206 /*0.989136*/,	16221 /*0.990051*/,	  16234 /*0.990845*/,	16248 /*0.991699*/,
  16260 /*0.992432*/,	16272 /*0.993164*/,	  16284 /*0.993896*/,	16294 /*0.994507*/,
  16305 /*0.995178*/,	16314 /*0.995728*/,	  16323 /*0.996277*/,	16331 /*0.996765*/,
  16339 /*0.997253*/,	16346 /*0.997681*/,	  16353 /*0.998108*/,	16358 /*0.998413*/,
  16364 /*0.998779*/,	16368 /*0.999023*/,	  16372 /*0.999268*/,	16376 /*0.999512*/,
  16379 /*0.999695*/,	16381 /*0.999817*/,	  16382 /*0.999878*/,	16383 /*0.999939*/,
  16384 /*1.000000*/,	16383 /*0.999939*/,	  16382 /*0.999878*/,	16381 /*0.999817*/,
  16379 /*0.999695*/,	16376 /*0.999512*/,	  16372 /*0.999268*/,	16368 /*0.999023*/,
  16364 /*0.998779*/,	16359 /*0.998474*/,	  16353 /*0.998108*/,	16346 /*0.997681*/,
  16339 /*0.997253*/,	16331 /*0.996765*/,	  16323 /*0.996277*/,	16314 /*0.995728*/,
  16305 /*0.995178*/,	16295 /*0.994568*/,	  16284 /*0.993896*/,	16272 /*0.993164*/,
  16260 /*0.992432*/,	16248 /*0.991699*/,	  16235 /*0.990906*/,	16221 /*0.990051*/,
  16206 /*0.989136*/,	16191 /*0.988220*/,	  16176 /*0.987305*/,	16159 /*0.986267*/,
  16142 /*0.985229*/,	16125 /*0.984192*/,	  16107 /*0.983093*/,	16088 /*0.981934*/,
  16069 /*0.980774*/,	16049 /*0.979553*/,	  16028 /*0.978271*/,	16007 /*0.976990*/,
  15986 /*0.975708*/,	15963 /*0.974304*/,	  15940 /*0.972900*/,	15917 /*0.971497*/,
  15893 /*0.970032*/,	15868 /*0.968506*/,	  15843 /*0.966980*/,	15817 /*0.965393*/,
  15790 /*0.963745*/,	15763 /*0.962097*/,	  15736 /*0.960449*/,	15707 /*0.958679*/,
  15678 /*0.956909*/,	15649 /*0.955139*/,	  15619 /*0.953308*/,	15588 /*0.951416*/,
  15557 /*0.949524*/,	15525 /*0.947571*/,	  15493 /*0.945618*/,	15460 /*0.943604*/,
  15426 /*0.941528*/,	15392 /*0.939453*/,	  15357 /*0.937317*/,	15322 /*0.935181*/,
  15286 /*0.932983*/,	15250 /*0.930786*/,	  15212 /*0.928467*/,	15175 /*0.926208*/,
  15137 /*0.923889*/,	15098 /*0.921509*/,	  15059 /*0.919128*/,	15019 /*0.916687*/,
  14978 /*0.914185*/,	14937 /*0.911682*/,	  14896 /*0.909180*/,	14853 /*0.906555*/,
  14811 /*0.903992*/,	14767 /*0.901306*/,	  14724 /*0.898682*/,	14679 /*0.895935*/,
  14635 /*0.893250*/,	14589 /*0.890442*/,	  14543 /*0.887634*/,	14496 /*0.884766*/,
  14450 /*0.881958*/,	14402 /*0.879028*/,	  14354 /*0.876099*/,	14305 /*0.873108*/,
  14256 /*0.870117*/,	14206 /*0.867065*/,	  14155 /*0.863953*/,	14105 /*0.860901*/,
  14053 /*0.857727*/,	14001 /*0.854553*/,	  13948 /*0.851318*/,	13896 /*0.848145*/,
  13842 /*0.844849*/,	13788 /*0.841553*/,	  13733 /*0.838196*/,	13679 /*0.834900*/,
  13623 /*0.831482*/,	13567 /*0.828064*/,	  13510 /*0.824585*/,	13453 /*0.821106*/,
  13395 /*0.817566*/,	13338 /*0.814087*/,	  13279 /*0.810486*/,	13219 /*0.806824*/,
  13160 /*0.803223*/,	13100 /*0.799561*/,	  13039 /*0.795837*/,	12978 /*0.792114*/,
  12917 /*0.788391*/,	12854 /*0.784546*/,	  12792 /*0.780762*/,	12729 /*0.776917*/,
  12665 /*0.773010*/,	12601 /*0.769104*/,	  12537 /*0.765198*/,	12472 /*0.761230*/,
  12407 /*0.757263*/,	12340 /*0.753174*/,	  12274 /*0.749146*/,	12207 /*0.745056*/,
  12140 /*0.740967*/,	12072 /*0.736816*/,	  12004 /*0.732666*/,	11936 /*0.728516*/,
  11866 /*0.724243*/,	11797 /*0.720032*/,	  11727 /*0.715759*/,	11657 /*0.711487*/,
  11585 /*0.707092*/,	11514 /*0.702759*/,	  11442 /*0.698364*/,	11371 /*0.694031*/,
  11298 /*0.689575*/,	11225 /*0.685120*/,	  11151 /*0.680603*/,	11078 /*0.676147*/,
  11003 /*0.671570*/,	10928 /*0.666992*/,	  10853 /*0.662415*/,	10778 /*0.657837*/,
  10702 /*0.653198*/,	10625 /*0.648499*/,	  10549 /*0.643860*/,	10472 /*0.639160*/,
  10394 /*0.634399*/,	10316 /*0.629639*/,	  10238 /*0.624878*/,	10159 /*0.620056*/,
  10081 /*0.615295*/,	10001 /*0.610413*/,	  9921 /*0.605530*/,	9841 /*0.600647*/,
  9761 /*0.595764*/,	9679 /*0.590759*/,	  9598 /*0.585815*/,	9517 /*0.580872*/,
  9434 /*0.575806*/,	9352 /*0.570801*/,	  9269 /*0.565735*/,	9186 /*0.560669*/,
  9103 /*0.555603*/,	9019 /*0.550476*/,	  8935 /*0.545349*/,	8851 /*0.540222*/,
  8766 /*0.535034*/,	8681 /*0.529846*/,	  8595 /*0.524597*/,	8510 /*0.519409*/,
  8424 /*0.514160*/,	8338 /*0.508911*/,	  8251 /*0.503601*/,	8163 /*0.498230*/,
  8076 /*0.492920*/,	7988 /*0.487549*/,	  7901 /*0.482239*/,	7812 /*0.476807*/,
  7724 /*0.471436*/,	7635 /*0.466003*/,	  7546 /*0.460571*/,	7456 /*0.455078*/,
  7367 /*0.449646*/,	7277 /*0.444153*/,	  7187 /*0.438660*/,	7096 /*0.433105*/,
  7006 /*0.427612*/,	6915 /*0.422058*/,	  6824 /*0.416504*/,	6732 /*0.410889*/,
  6640 /*0.405273*/,	6548 /*0.399658*/,	  6455 /*0.393982*/,	6363 /*0.388367*/,
  6270 /*0.382690*/,	6178 /*0.377075*/,	  6084 /*0.371338*/,	5991 /*0.365662*/,
  5897 /*0.359924*/,	5804 /*0.354248*/,	  5709 /*0.348450*/,	5615 /*0.342712*/,
  5520 /*0.336914*/,	5426 /*0.331177*/,	  5331 /*0.325378*/,	5236 /*0.319580*/,
  5140 /*0.313721*/,	5044 /*0.307861*/,	  4949 /*0.302063*/,	4852 /*0.296143*/,
  4757 /*0.290344*/,	4660 /*0.284424*/,	  4564 /*0.278564*/,	4467 /*0.272644*/,
  4371 /*0.266785*/,	4273 /*0.260803*/,	  4177 /*0.254944*/,	4079 /*0.248962*/,
  3982 /*0.243042*/,	3884 /*0.237061*/,	  3787 /*0.231140*/,	3688 /*0.225098*/,
  3591 /*0.219177*/,	3492 /*0.213135*/,	  3394 /*0.207153*/,	3296 /*0.201172*/,
  3197 /*0.195129*/,	3099 /*0.189148*/,	  2999 /*0.183044*/,	2901 /*0.177063*/,
  2802 /*0.171021*/,	2703 /*0.164978*/,	  2603 /*0.158875*/,	2504 /*0.152832*/,
  2405 /*0.146790*/,	2306 /*0.140747*/,	  2206 /*0.134644*/,	2107 /*0.128601*/,
  2006 /*0.122437*/,	1907 /*0.116394*/,	  1807 /*0.110291*/,	1706 /*0.104126*/,
  1607 /*0.098083*/,	1506 /*0.091919*/,	  1407 /*0.085876*/,	1306 /*0.079712*/,
  1206 /*0.073608*/,	1106 /*0.067505*/,	  1006 /*0.061401*/,	905 /*0.055237*/,
  805 /*0.049133*/,		704 /*0.042969*/,	  604 /*0.036865*/,		503 /*0.030701*/,
  403 /*0.024597*/,		302 /*0.018433*/,	  202 /*0.012329*/,		101 /*0.006165*/,
  0 /*0.000000*/,		-99 /*-0.006042*/,	  -200 /*-0.012207*/,	-300 /*-0.018311*/,
  -401 /*-0.024475*/,	-501 /*-0.030579*/,	  -602 /*-0.036743*/,	-701 /*-0.042786*/,
  -802 /*-0.048950*/,	-902 /*-0.055054*/,	  -1003 /*-0.061218*/,	-1103 /*-0.067322*/,
  -1204 /*-0.073486*/,	-1303 /*-0.079529*/,  -1404 /*-0.085693*/,	-1504 /*-0.091797*/,
  -1604 /*-0.097900*/,	-1704 /*-0.104004*/,  -1804 /*-0.110107*/,	-1904 /*-0.116211*/,
  -2004 /*-0.122314*/,	-2104 /*-0.128418*/,  -2203 /*-0.134460*/,	-2303 /*-0.140564*/,
  -2402 /*-0.146606*/,	-2502 /*-0.152710*/,  -2601 /*-0.158752*/,	-2700 /*-0.164795*/,
  -2799 /*-0.170837*/,	-2898 /*-0.176880*/,  -2997 /*-0.182922*/,	-3096 /*-0.188965*/,
  -3194 /*-0.194946*/,	-3293 /*-0.200989*/,  -3391 /*-0.206970*/,	-3490 /*-0.213013*/,
  -3588 /*-0.218994*/,	-3686 /*-0.224976*/,  -3784 /*-0.230957*/,	-3881 /*-0.236877*/,
  -3979 /*-0.242859*/,	-4076 /*-0.248779*/,  -4174 /*-0.254761*/,	-4271 /*-0.260681*/,
  -4368 /*-0.266602*/,	-4464 /*-0.272461*/,  -4562 /*-0.278442*/,	-4657 /*-0.284241*/,
  -4754 /*-0.290161*/,	-4850 /*-0.296021*/,  -4946 /*-0.301880*/,	-5041 /*-0.307678*/,
  -5137 /*-0.313538*/,	-5233 /*-0.319397*/,  -5328 /*-0.325195*/,	-5423 /*-0.330994*/,
  -5518 /*-0.336792*/,	-5613 /*-0.342590*/,  -5706 /*-0.348267*/,	-5801 /*-0.354065*/,
  -5894 /*-0.359741*/,	-5989 /*-0.365540*/,  -6082 /*-0.371216*/,	-6175 /*-0.376892*/,
  -6268 /*-0.382568*/,	-6361 /*-0.388245*/,  -6453 /*-0.393860*/,	-6546 /*-0.399536*/,
  -6637 /*-0.405090*/,	-6729 /*-0.410706*/,  -6821 /*-0.416321*/,	-6912 /*-0.421875*/,
  -7004 /*-0.427490*/,	-7094 /*-0.432983*/,  -7185 /*-0.438538*/,	-7274 /*-0.443970*/,
  -7365 /*-0.449524*/,	-7454 /*-0.454956*/,  -7544 /*-0.460449*/,	-7632 /*-0.465820*/,
  -7722 /*-0.471313*/,	-7810 /*-0.476685*/,  -7898 /*-0.482056*/,	-7986 /*-0.487427*/,
  -8074 /*-0.492798*/,	-8161 /*-0.498108*/,  -8248 /*-0.503418*/,	-8335 /*-0.508728*/,
  -8421 /*-0.513977*/,	-8508 /*-0.519287*/,  -8593 /*-0.524475*/,	-8679 /*-0.529724*/,
  -8763 /*-0.534851*/,	-8849 /*-0.540100*/,  -8933 /*-0.545227*/,	-9017 /*-0.550354*/,
  -9100 /*-0.555420*/,	-9184 /*-0.560547*/,  -9267 /*-0.565613*/,	-9350 /*-0.570679*/,
  -9432 /*-0.575684*/,	-9514 /*-0.580688*/,  -9596 /*-0.585693*/,	-9677 /*-0.590637*/,
  -9759 /*-0.595642*/,	-9839 /*-0.600525*/,  -9919 /*-0.605408*/,	-9999 /*-0.610291*/,
  -10079 /*-0.615173*/, -10157 /*-0.619934*/, -10236 /*-0.624756*/, -10314 /*-0.629517*/,
  -10392 /*-0.634277*/, -10469 /*-0.638977*/, -10547 /*-0.643738*/, -10623 /*-0.648376*/,
  -10700 /*-0.653076*/, -10776 /*-0.657715*/, -10851 /*-0.662292*/, -10926 /*-0.666870*/,
  -11001 /*-0.671448*/, -11076 /*-0.676025*/, -11149 /*-0.680481*/, -11223 /*-0.684998*/,
  -11296 /*-0.689453*/, -11369 /*-0.693909*/, -11440 /*-0.698242*/, -11513 /*-0.702698*/,
  -11583 /*-0.706970*/, -11655 /*-0.711365*/, -11725 /*-0.715637*/, -11795 /*-0.719910*/,
  -11864 /*-0.724121*/, -11934 /*-0.728394*/, -12002 /*-0.732544*/, -12070 /*-0.736694*/,
  -12138 /*-0.740845*/, -12205 /*-0.744934*/, -12273 /*-0.749084*/, -12339 /*-0.753113*/,
  -12405 /*-0.757141*/, -12470 /*-0.761108*/, -12535 /*-0.765076*/, -12599 /*-0.768982*/,
  -12664 /*-0.772949*/, -12727 /*-0.776794*/, -12790 /*-0.780640*/, -12852 /*-0.784424*/,
  -12915 /*-0.788269*/, -12976 /*-0.791992*/, -13038 /*-0.795776*/, -13098 /*-0.799438*/,
  -13158 /*-0.803101*/, -13218 /*-0.806763*/, -13277 /*-0.810364*/, -13336 /*-0.813965*/,
  -13394 /*-0.817505*/, -13452 /*-0.821045*/, -13509 /*-0.824524*/, -13565 /*-0.827942*/,
  -13621 /*-0.831360*/, -13677 /*-0.834778*/, -13732 /*-0.838135*/, -13787 /*-0.841492*/,
  -13841 /*-0.844788*/, -13894 /*-0.848022*/, -13947 /*-0.851257*/, -14000 /*-0.854492*/,
  -14051 /*-0.857605*/, -14103 /*-0.860779*/, -14154 /*-0.863892*/, -14204 /*-0.866943*/,
  -14254 /*-0.869995*/, -14303 /*-0.872986*/, -14352 /*-0.875977*/, -14400 /*-0.878906*/,
  -14448 /*-0.881836*/, -14495 /*-0.884705*/, -14542 /*-0.887573*/, -14588 /*-0.890381*/,
  -14633 /*-0.893127*/, -14678 /*-0.895874*/, -14723 /*-0.898621*/, -14766 /*-0.901245*/,
  -14810 /*-0.903931*/, -14852 /*-0.906494*/, -14895 /*-0.909119*/, -14936 /*-0.911621*/,
  -14977 /*-0.914124*/, -15018 /*-0.916626*/, -15058 /*-0.919067*/, -15097 /*-0.921448*/,
  -15136 /*-0.923828*/, -15174 /*-0.926147*/, -15211 /*-0.928406*/, -15249 /*-0.930725*/,
  -15285 /*-0.932922*/, -15321 /*-0.935120*/, -15356 /*-0.937256*/, -15391 /*-0.939392*/,
  -15425 /*-0.941467*/, -15459 /*-0.943542*/, -15492 /*-0.945557*/, -15524 /*-0.947510*/,
  -15556 /*-0.949463*/, -15587 /*-0.951355*/, -15618 /*-0.953247*/, -15648 /*-0.955078*/,
  -15678 /*-0.956909*/, -15706 /*-0.958618*/, -15735 /*-0.960388*/, -15762 /*-0.962036*/,
  -15790 /*-0.963745*/, -15816 /*-0.965332*/, -15842 /*-0.966919*/, -15867 /*-0.968445*/,
  -15892 /*-0.969971*/, -15916 /*-0.971436*/, -15940 /*-0.972900*/, -15963 /*-0.974304*/,
  -15985 /*-0.975647*/, -16007 /*-0.976990*/, -16028 /*-0.978271*/, -16049 /*-0.979553*/,
  -16068 /*-0.980713*/, -16088 /*-0.981934*/, -16106 /*-0.983032*/, -16125 /*-0.984192*/,
  -16142 /*-0.985229*/, -16159 /*-0.986267*/, -16175 /*-0.987244*/, -16191 /*-0.988220*/,
  -16206 /*-0.989136*/, -16220 /*-0.989990*/, -16234 /*-0.990845*/, -16247 /*-0.991638*/,
  -16260 /*-0.992432*/, -16272 /*-0.993164*/, -16283 /*-0.993835*/, -16294 /*-0.994507*/,
  -16304 /*-0.995117*/, -16314 /*-0.995728*/, -16323 /*-0.996277*/, -16331 /*-0.996765*/,
  -16339 /*-0.997253*/, -16346 /*-0.997681*/, -16353 /*-0.998108*/, -16358 /*-0.998413*/,
  -16364 /*-0.998779*/, -16368 /*-0.999023*/, -16372 /*-0.999268*/, -16376 /*-0.999512*/,
  -16379 /*-0.999695*/, -16381 /*-0.999817*/, -16382 /*-0.999878*/, -16383 /*-0.999939*/,
  -16384 /*-1.000000*/, -16383 /*-0.999939*/, -16382 /*-0.999878*/, -16381 /*-0.999817*/,
  -16379 /*-0.999695*/, -16376 /*-0.999512*/, -16372 /*-0.999268*/, -16368 /*-0.999023*/,
  -16364 /*-0.998779*/, -16359 /*-0.998474*/, -16353 /*-0.998108*/, -16346 /*-0.997681*/,
  -16339 /*-0.997253*/, -16332 /*-0.996826*/, -16323 /*-0.996277*/, -16314 /*-0.995728*/,
  -16305 /*-0.995178*/, -16295 /*-0.994568*/, -16284 /*-0.993896*/, -16273 /*-0.993225*/,
  -16260 /*-0.992432*/, -16248 /*-0.991699*/, -16235 /*-0.990906*/, -16221 /*-0.990051*/,
  -16206 /*-0.989136*/, -16191 /*-0.988220*/, -16176 /*-0.987305*/, -16160 /*-0.986328*/,
  -16143 /*-0.985291*/, -16125 /*-0.984192*/, -16107 /*-0.983093*/, -16088 /*-0.981934*/,
  -16069 /*-0.980774*/, -16049 /*-0.979553*/, -16029 /*-0.978333*/, -16007 /*-0.976990*/,
  -15986 /*-0.975708*/, -15963 /*-0.974304*/, -15941 /*-0.972961*/, -15917 /*-0.971497*/,
  -15893 /*-0.970032*/, -15868 /*-0.968506*/, -15843 /*-0.966980*/, -15817 /*-0.965393*/,
  -15791 /*-0.963806*/, -15763 /*-0.962097*/, -15736 /*-0.960449*/, -15707 /*-0.958679*/,
  -15679 /*-0.956970*/, -15649 /*-0.955139*/, -15619 /*-0.953308*/, -15588 /*-0.951416*/,
  -15557 /*-0.949524*/, -15525 /*-0.947571*/, -15493 /*-0.945618*/, -15460 /*-0.943604*/,
  -15426 /*-0.941528*/, -15392 /*-0.939453*/, -15357 /*-0.937317*/, -15322 /*-0.935181*/,
  -15286 /*-0.932983*/, -15250 /*-0.930786*/, -15213 /*-0.928528*/, -15175 /*-0.926208*/,
  -15137 /*-0.923889*/, -15098 /*-0.921509*/, -15059 /*-0.919128*/, -15019 /*-0.916687*/,
  -14979 /*-0.914246*/, -14937 /*-0.911682*/, -14896 /*-0.909180*/, -14854 /*-0.906616*/,
  -14811 /*-0.903992*/, -14768 /*-0.901367*/, -14724 /*-0.898682*/, -14680 /*-0.895996*/,
  -14635 /*-0.893250*/, -14589 /*-0.890442*/, -14544 /*-0.887695*/, -14497 /*-0.884827*/,
  -14450 /*-0.881958*/, -14402 /*-0.879028*/, -14354 /*-0.876099*/, -14305 /*-0.873108*/,
  -14256 /*-0.870117*/, -14206 /*-0.867065*/, -14156 /*-0.864014*/, -14105 /*-0.860901*/,
  -14053 /*-0.857727*/, -14002 /*-0.854614*/, -13949 /*-0.851379*/, -13896 /*-0.848145*/,
  -13842 /*-0.844849*/, -13789 /*-0.841614*/, -13734 /*-0.838257*/, -13679 /*-0.834900*/,
  -13623 /*-0.831482*/, -13567 /*-0.828064*/, -13511 /*-0.824646*/, -13454 /*-0.821167*/,
  -13396 /*-0.817627*/, -13338 /*-0.814087*/, -13279 /*-0.810486*/, -13220 /*-0.806885*/,
  -13160 /*-0.803223*/, -13100 /*-0.799561*/, -13040 /*-0.795898*/, -12978 /*-0.792114*/,
  -12917 /*-0.788391*/, -12855 /*-0.784607*/, -12792 /*-0.780762*/, -12729 /*-0.776917*/,
  -12666 /*-0.773071*/, -12602 /*-0.769165*/, -12537 /*-0.765198*/, -12472 /*-0.761230*/,
  -12407 /*-0.757263*/, -12341 /*-0.753235*/, -12275 /*-0.749207*/, -12208 /*-0.745117*/,
  -12140 /*-0.740967*/, -12073 /*-0.736877*/, -12004 /*-0.732666*/, -11936 /*-0.728516*/,
  -11867 /*-0.724304*/, -11798 /*-0.720093*/, -11727 /*-0.715759*/, -11657 /*-0.711487*/,
  -11586 /*-0.707153*/, -11515 /*-0.702820*/, -11443 /*-0.698425*/, -11371 /*-0.694031*/,
  -11298 /*-0.689575*/, -11226 /*-0.685181*/, -11152 /*-0.680664*/, -11078 /*-0.676147*/,
  -11004 /*-0.671631*/, -10929 /*-0.667053*/, -10854 /*-0.662476*/, -10778 /*-0.657837*/,
  -10703 /*-0.653259*/, -10626 /*-0.648560*/, -10550 /*-0.643921*/, -10472 /*-0.639160*/,
  -10395 /*-0.634460*/, -10317 /*-0.629700*/, -10239 /*-0.624939*/, -10160 /*-0.620117*/,
  -10081 /*-0.615295*/, -10002 /*-0.610474*/, -9922 /*-0.605591*/,	-9842 /*-0.600708*/,
  -9761 /*-0.595764*/,	-9680 /*-0.590820*/,  -9598 /*-0.585815*/,	-9517 /*-0.580872*/,
  -9435 /*-0.575867*/,	-9353 /*-0.570862*/,  -9270 /*-0.565796*/,	-9187 /*-0.560730*/,
  -9103 /*-0.555603*/,	-9020 /*-0.550537*/,  -8936 /*-0.545410*/,	-8852 /*-0.540283*/,
  -8766 /*-0.535034*/,	-8682 /*-0.529907*/,  -8596 /*-0.524658*/,	-8511 /*-0.519470*/,
  -8424 /*-0.514160*/,	-8338 /*-0.508911*/,  -8251 /*-0.503601*/,	-8164 /*-0.498291*/,
  -8077 /*-0.492981*/,	-7989 /*-0.487610*/,  -7901 /*-0.482239*/,	-7813 /*-0.476868*/,
  -7725 /*-0.471497*/,	-7636 /*-0.466064*/,  -7547 /*-0.460632*/,	-7457 /*-0.455139*/,
  -7368 /*-0.449707*/,	-7278 /*-0.444214*/,  -7188 /*-0.438721*/,	-7097 /*-0.433167*/,
  -7007 /*-0.427673*/,	-6915 /*-0.422058*/,  -6825 /*-0.416565*/,	-6733 /*-0.410950*/,
  -6640 /*-0.405273*/,	-6549 /*-0.399719*/,  -6456 /*-0.394043*/,	-6364 /*-0.388428*/,
  -6271 /*-0.382751*/,	-6178 /*-0.377075*/,  -6085 /*-0.371399*/,	-5992 /*-0.365723*/,
  -5898 /*-0.359985*/,	-5804 /*-0.354248*/,  -5710 /*-0.348511*/,	-5616 /*-0.342773*/,
  -5521 /*-0.336975*/,	-5427 /*-0.331238*/,  -5331 /*-0.325378*/,	-5237 /*-0.319641*/,
  -5141 /*-0.313782*/,	-5045 /*-0.307922*/,  -4950 /*-0.302124*/,	-4853 /*-0.296204*/,
  -4758 /*-0.290405*/,	-4661 /*-0.284485*/,  -4565 /*-0.278625*/,	-4468 /*-0.272705*/,
  -4372 /*-0.266846*/,	-4274 /*-0.260864*/,  -4178 /*-0.255005*/,	-4080 /*-0.249023*/,
  -3983 /*-0.243103*/,	-3885 /*-0.237122*/,  -3788 /*-0.231201*/,	-3689 /*-0.225159*/,
  -3592 /*-0.219238*/,	-3493 /*-0.213196*/,  -3394 /*-0.207153*/,	-3297 /*-0.201233*/,
  -3198 /*-0.195190*/,	-3099 /*-0.189148*/,  -3000 /*-0.183105*/,	-2902 /*-0.177124*/,
  -2802 /*-0.171021*/,	-2704 /*-0.165039*/,  -2604 /*-0.158936*/,	-2505 /*-0.152893*/,
  -2405 /*-0.146790*/,	-2307 /*-0.140808*/,  -2206 /*-0.134644*/,	-2107 /*-0.128601*/,
  -2007 /*-0.122498*/,	-1908 /*-0.116455*/,  -1808 /*-0.110352*/,	-1707 /*-0.104187*/,
  -1608 /*-0.098145*/,	-1507 /*-0.091980*/,  -1407 /*-0.085876*/,	-1307 /*-0.079773*/,
  -1207 /*-0.073669*/,	-1106 /*-0.067505*/,  -1007 /*-0.061462*/,	-906 /*-0.055298*/,
  -806 /*-0.049194*/,	-705 /*-0.043030*/,	  -605 /*-0.036926*/,	-504 /*-0.030762*/,
  -404 /*-0.024658*/,	-303 /*-0.018494*/,	  -203 /*-0.012390*/,	-102 /*-0.006226*/
};
#endif

class FixedMath
{
public:
	static inline ion::Fixed32 Abs(ion::Fixed32 fp)
	{
		fp.m_value = std::abs(fp.m_value);
		return fp;
	}

#if ION_CONFIG_REAL_IS_FIXED_POINT
	FixedMath() {}

	static const int32_t base = ion::Fixed32::FractionBits;

	// https://gist.github.com/Madsy/1088393
	static inline Fixed32 exp(Fixed32 value)
	{
		int32_t val = value.m_value;
		int32_t x = val;
		x = x - (((int64_t)x * (fp_ln(x) - val)) >> base);
		x = x - (((int64_t)x * (fp_ln(x) - val)) >> base);
		x = x - (((int64_t)x * (fp_ln(x) - val)) >> base);
		x = x - (((int64_t)x * (fp_ln(x) - val)) >> base);
		value.m_value = x;
		return value;
	}



	template <typename T, size_t U>
	static inline FixedPoint<T, U> Abs(FixedPoint<T, U> fp)
	{
		fp.m_value = std::abs(fp.m_value);
		return fp;
	}

	static inline Fixed32 log(Fixed32 f32)
	{
		f32.m_value = fp_ln(f32.m_value);
		return f32;
	}

	// https://geekshavefeelings.com/posts/fixed-point-atan2
	// Note: page has incorrect code, use:
	// https://geekshavefeelings.com/x/wp-content/uploads/2012/02/fxpt_atan2.c
	/*
	 * fxpt_atan2.c
	 *
	 * Copyright (C) 2012, Xo Wang
	 *
	 * Permission is hereby granted, free of charge, to any person obtaining a copy of
	 * this software and associated documentation files (the "Software"), to deal in
	 * the Software without restriction, including without limitation the rights to
	 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
	 * of the Software, and to permit persons to whom the Software is furnished to do
	 * so, subject to the following conditions:
	 *
	 * The above copyright notice and this permission notice shall be included in all
	 * copies or substantial portions of the Software.
	 *
	 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	 * SOFTWARE.
	 */
	/**
	 * 16-bit fixed point four-quadrant arctangent. Given some Cartesian vector
	 * (x, y), find the angle subtended by the vector and the positive x-axis.
	 *
	 * The value returned is in units of 1/65536ths of one turn. This allows the use
	 * of the full 16-bit unsigned range to represent a turn. e.g. 0x0000 is 0
	 * radians, 0x8000 is pi radians, and 0xFFFF is (65535 / 32768) * pi radians.
	 *
	 * Because the magnitude of the input vector does not change the angle it
	 * represents, the inputs can be in any signed 16-bit fixed-point format.
	 *
	 * @param y y-coordinate in signed 16-bit
	 * @param x x-coordinate in signed 16-bit
	 * @return angle in (val / 32768) * pi radian increments from 0x0000 to 0xFFFF
	 */
	static uint16_t fxpt_atan2(const int16_t y, const int16_t x)
	{
#if 1
		const int16_t correctionMulti = 2847;
		const int16_t unrotatedMulti = 11039;
#else  // Original
		static inline int16_t q15_from_double(const double d) { return static_cast<int16_t>(lrint(d * 32768)); }
		static const double M_1_PI = 0.31830988618379067154;
		const int16_t correctionMulti = q15_from_double(0.273 * M_1_PI);
		const int16_t unrotatedMulti = q15_from_double(0.25 + 0.273 * M_1_PI);
#endif

		if (x == y)
		{  // x/y or y/x would return -1 since 1 isn't representable
			if (y > 0)
			{  // 1/8
				return 8192;
			}
			else if (y < 0)
			{  // 5/8
				return 40960;
			}
			else
			{  // x = y = 0
				return 0;
			}
		}
		const int16_t nabs_y = s16_nabs(y), nabs_x = s16_nabs(x);
		if (nabs_x < nabs_y)
		{  // octants 1, 4, 5, 8
			const int16_t y_over_x = q15_div(y, x);
			const int16_t correction = q15_mul(correctionMulti, s16_nabs(y_over_x));
			const int16_t unrotated = q15_mul(unrotatedMulti + correction, y_over_x);
			if (x > 0)
			{  // octants 1, 8
				return unrotated;
			}
			else
			{  // octants 4, 5
				return 32768 + unrotated;
			}
		}
		else
		{  // octants 2, 3, 6, 7
			const int16_t x_over_y = q15_div(x, y);
			const int16_t correction = q15_mul(correctionMulti, s16_nabs(x_over_y));
			const int16_t unrotated = q15_mul(unrotatedMulti + correction, x_over_y);
			if (y > 0)
			{  // octants 2, 3
				return 16384 - unrotated;
			}
			else
			{  // octants 6, 7
				return 49152 - unrotated;
			}
		}
	}

	static Fixed32 Cos(ion::Fixed32 v)
	{
		v += Math::Pi() / 2;
		return Sin(v);
	}

	static inline Fixed32 Sin(ion::Fixed32 v)
	{
		// PrintSinValues();

		if (v < 0)
		{
			int diff = static_cast<int>(-v / (Fraction<int64_t>(2) * Math::Pi32()));
			v += (Fraction<int64_t>(diff * 2) * Math::Pi32());
		}
		v = v / (Fraction<int64_t>(2) * Math::Pi32());
		int index = static_cast<int>(v * Fixed32(NumSinEntries)) % NumSinEntries;
		auto modOne = v % Fixed32(1);

		Fixed32 a;
		a.m_value = gSinValues[index];
		Fixed32 b;
		b.m_value = gSinValues[(index + 1) & (NumSinEntries - 1)];
		return a * (Fixed32(1) - modOne) + (b * modOne);
	}

private:
	static void PrintSinValues();

	// https://gist.github.com/Madsy/1088393
	static int32_t fp_ln(int32_t val)
	{
		int32_t fracv = 0, intv = 0, y = 0, ysq = 0, fracr = 0, bitpos = 0;
		/*
		fracv    -    initial fraction part from "val"
		intv    -    initial integer part from "val"
		y        -    (fracv-1)/(fracv+1)
		ysq        -    y*y
		fracr    -    ln(fracv)
		bitpos    -    integer part of log2(val)
		*/

		// const int32_t ILN2 = 94548;        /* 1/ln(2) with 2^16 as base*/
		// const int32_t ILOG2E = 45426;    /* 1/log2(e) with 2^16 as base */
		// double tmp = 1 / std::log2(2.71828);
		const int32_t ILOG2E = ion::Fixed32(ion::Fraction32(693148, 1000000)).m_value;
		const int32_t ln_denoms[] = {
		  (1 << base) / 1,	(1 << base) / 3,  (1 << base) / 5,	(1 << base) / 7,  (1 << base) / 9,	(1 << base) / 11,
		  (1 << base) / 13, (1 << base) / 15, (1 << base) / 17, (1 << base) / 19, (1 << base) / 21,
		};

		/* compute fracv and intv */
		bitpos = (base - 1) - ion::CountLeadingZeroes(val);
		if (bitpos >= 0)
		{
			++bitpos;
			fracv = val >> bitpos;
		}
		else if (bitpos < 0)
		{
			/* fracr = val / 2^-(bitpos) */
			++bitpos;
			fracv = val << (-bitpos);
		}

		// bitpos is the integer part of ln(val), but in log2, so we convert
		// ln(val) = log2(val) / log2(e)
		intv = bitpos * ILOG2E;

		// y = (ln_fraction_value−1)/(ln_fraction_value+1)
		y = ((int64_t)(fracv - (1 << base)) << base) / (fracv + (1 << base));

		ysq = (y * y) >> base;
		fracr = ln_denoms[10];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[9];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[8];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[7];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[6];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[5];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[4];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[3];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[2];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[1];
		fracr = (((int64_t)fracr * ysq) >> base) + ln_denoms[0];
		fracr = ((int64_t)fracr * (y << 1)) >> base;

		return intv + fracr;
	}

	template <typename T>
	static inline T s16_nabs(const T j)
	{
		if constexpr ((((int16_t{0}) - 1) >> 1) == ((int16_t{0}) - 1))
		{
			// signed right shift sign-extends (arithmetic)
			constexpr size_t Shift = sizeof(T) * 8 - 1;
			const T negSign = ~(j >> Shift);  // splat sign bit into all 16 and complement
											  // if j is positive (negSign is -1), xor will invert j and sub will add 1
											  // otherwise j is unchanged
			return (j ^ negSign) - negSign;
		}
		else
		{
			return (j < 0 ? j : -j);
		}
	}

	static inline int16_t q15_div(const int16_t numer, const int16_t denom) { return ((int32_t)numer << 15) / denom; }

	static inline int16_t q15_mul(const int16_t j, const int16_t k)
	{
		const int32_t intermediate = j * (int32_t)k;
#if 0	 // don't round
			return intermediate >> 15;
#elif 0	 // biased rounding
		return (intermediate + 0x4000) >> 15;
#else	 // unbiased rounding
		return static_cast<int16_t>((intermediate + ((intermediate & 0x7FFF) == 0x4000 ? 0 : 0x4000)) >> 15);
#endif
	}
	#endif
};

#if ION_CONFIG_REAL_IS_FIXED_POINT

[[nodiscard]] inline ion::Fixed32 exp(ion::Fixed32 value) { return FixedMath::exp(value); }

[[nodiscard]] inline ion::Fixed32 cos(ion::Fixed32 value) { return FixedMath::Cos(value); }

[[nodiscard]] inline ion::Fixed32 sin(ion::Fixed32 value) { return FixedMath::Sin(value); }

[[nodiscard]] inline ion::Fixed32 log(ion::Fixed32 value) { return FixedMath::log(value); }

template <typename T, unsigned int U>
[[nodiscard]] inline ion::FixedPoint<T, U> atan2(ion::FixedPoint<T, U> y, ion::FixedPoint<T, U> x)
{
	y = ((y < 1) ? ((y > -1) ? y : -1) : 1);
	x = ((x < 1) ? ((x > -1) ? x : -1) : 1);
	T yi = static_cast<T>(y * INT16_MAX);
	T xi = static_cast<T>(x * INT16_MAX);
	int32_t at2 = FixedMath::fxpt_atan2(static_cast<int16_t>(yi), static_cast<int16_t>(xi));
	ion::FixedPoint<T, U> result(ion::Fraction<T>(static_cast<T>(at2), INT16_MAX));
	return result * ion::Math::Pi<ion::FixedPoint<T, U>>();
}

template <typename T, unsigned int U>
[[nodiscard]] inline ion::FixedPoint<T, U> fmod(ion::FixedPoint<T, U> x, ion::FixedPoint<T, U> y)
{
	return x % y;
}

template <typename T, unsigned int U>
[[nodiscard]] inline bool IsNormal(ion::FixedPoint<T, U> y)
{
	return !isnan(y) && y != 0;
}

template <typename T, unsigned int U>
[[nodiscard]] inline bool SignBit(ion::FixedPoint<T, U> y)
{
	return y < 0;
}

[[nodiscard]] inline uint64_t sqrt(uint64_t v)
{
	uint64_t t, q, b, r;
	r = v;			 // r = v - x²
	b = 0x40000000;	 // a²
	q = 0;			 // 2ax
	while (b > 0)
	{
		t = q + b;	 // t = 2ax + a²
		q >>= 1;	 // if a' = a/2, then q' = q/2
		if (r >= t)	 // if (v - x²) >= 2ax + a²
		{
			r -= t;	 // r' = (v - x²) - (2ax + a²)
			q += b;	 // if x' = (x + a) then ax' = ax + a², thus q' = q' + b
		}
		b >>= 2;  // if a' = a/2, then b' = b / 4
	}
	return q;
}

[[nodiscard]] inline ion::Fixed32 pow(ion::Fixed32 value, int /*n*/) noexcept
{
	ION_ASSERT_FMT_IMMEDIATE(false, "not implemented");
	return value;
}

template <>
[[nodiscard]] inline ion::Fixed32 round(ion::Fixed32 value) noexcept
{
	return ion::Fixed32{static_cast<int16_t>(value + (ion::Fixed32(ion::Fraction64(1, 2))))};
}

[[nodiscard]] inline ion::Fixed32 nextafter(ion::Fixed32 from, ion::Fixed32 to) noexcept
{
	ION_ASSERT(from != to, "Invalid nextafter");
	static_assert(std::numeric_limits<ion::Fixed32>::min() > 0, "Invalid min");
	if (from < to)
	{
		return from + std::numeric_limits<ion::Fixed32>::min();
	}
	else  // if (from > to)
	{
		return from - std::numeric_limits<ion::Fixed32>::min();
	}
	// return to;
}

[[nodiscard]] inline bool isfinite(ion::Fixed32 value) noexcept
{
	return (value > ion::Fixed32::GetNegativeInfinity()) && (value < ion::Fixed32::GetInfinity());
}

[[nodiscard]] constexpr inline bool isnan(ion::Fixed32 value) noexcept
{
	return value.isnan();
	// return value.Compare(0) == ion::Fixed32::ComparatorResult::Incomparable;
}

#ifdef ION_INT128
[[nodiscard]] inline bool isfinite(ion::Fixed64 value) noexcept
{
	return (value > ion::Fixed64::GetNegativeInfinity()) && (value < ion::Fixed64::GetInfinity());
}

[[nodiscard]] constexpr inline bool isnan(ion::Fixed64 value) noexcept
{
	return value.Compare(0) == ion::Fixed64::ComparatorResult::Incomparable;
}
#endif
#endif


template <typename T>
[[nodiscard]] inline ion::Fraction<T> sqrt(ion::Fraction<T> fraction)
{
	const T scale = 1 << (sizeof(T) * 2);
	const T scaleSqrt = static_cast<T>(ion::sqrt(uint64_t(scale)));

	ION_ASSERT(fraction.Numerator() >= 0 && fraction.Denominator() >= 0, "Invalid input");
	T val = static_cast<T>(fraction);
	if (val > scale)
	{
		val = static_cast<T>(ion::sqrt(uint64_t(val)));
		return ion::Fraction<T>(val, 1);
	}
	else
	{
		val = static_cast<T>(fraction * scale);
		val = static_cast<T>(ion::sqrt(uint64_t(val)));
		return ion::Fraction<T>(val, scaleSqrt);
	}
}

template<>
[[nodiscard]] inline ion::Fixed32 sqrt(ion::Fixed32 x)
{
	ION_ASSERT_FMT_IMMEDIATE(x >= 0 && !std::isinf(static_cast<float>(x)), "Invalid input");
	if (x < ion::Fraction32(1, 100))
	{
		return ion::Fixed32(0u);
	}

	ion::Fixed32 currentVal(x);
	currentVal *= ion::Fraction32(1, 2);

	int i = ((1 << 5) | static_cast<int>(x));
	while ((i >>= 1) != 0)
	{
		currentVal += x / currentVal;
		currentVal *= ion::Fraction32(1, 2);
	}
	return currentVal;
}

template<>
[[nodiscard]] inline ion::Fixed32 Absf(ion::Fixed32 value) noexcept { return FixedMath::Abs(value); }

template <>
[[nodiscard]] constexpr ion::Fixed32 Reciprocal(const ion::Fixed32 value)
{
#if ION_CONFIG_FAST_MATH
	ion::Fraction32 fraction(value);
	return ion::Fixed32(ion::Fraction(fraction.Denominator(), fraction.Numerator()));
#else
	return ion::Fixed32(1) / value;
#endif
}

template <typename T>
constexpr T ConvertRealTo(const ion::Fixed32& value)
{
	return value.ConvertTo<T>();
}


}  // namespace ion

